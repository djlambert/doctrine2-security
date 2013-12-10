<?php
/**
 * Copyright (C) 2013 Derek J. Lambert
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is furnished
 * to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

namespace CrEOF\Security\Mapping;

use CrEOF\Security\Exception\RuntimeException;
use CrEOF\Security\Mapping\Driver\AbstractFileDriver;
use CrEOF\Security\Mapping\Driver\AnnotationDriverInterface;
use CrEOF\Security\Mapping\Driver\ChainDriver;
use Doctrine\Common\Annotations\Reader;
use Doctrine\ORM\Mapping\ClassMetadata;
use Doctrine\Common\Persistence\Mapping\Driver\DefaultFileLocator;
use Doctrine\Common\Persistence\Mapping\Driver\SymfonyFileLocator;
use Doctrine\Common\Persistence\Mapping\Driver\MappingDriver;
use Doctrine\Common\Persistence\Mapping\Driver\MappingDriverChain;
use Doctrine\ORM\EntityManager;

/**
 * The extension metadata factory is responsible for extension driver initialization and fully reading the extension metadata
 *
 * @author  Derek J. Lambert <dlambert@dereklambert.com>
 * @license http://dlambert.mit-license.org MIT
 */
class ExtensionMetadataFactory
{
    /**
     * Extension driver
     *
     * @var DriverInterface
     */
    protected $driver;

    /**
     * Object manager, entity or document
     *
     * @var EntityManager
     */
    protected $entityManager;

    /**
     * Extension namespace
     *
     * @var string
     */
    protected $extensionNamespace;

    /**
     * Custom annotation reader
     *
     * @var Reader
     */
    protected $annotationReader;

    /**
     * Initializes extension driver
     *
     * @param EntityManager $entityManager
     * @param string        $extensionNamespace
     * @param Reader        $annotationReader
     */
    public function __construct(EntityManager $entityManager, $extensionNamespace, Reader $annotationReader)
    {
        $this->entityManager      = $entityManager;
        $this->extensionNamespace = $extensionNamespace;
        $this->annotationReader   = $annotationReader;
        $this->driver             = $this->getDriver($entityManager->getConfiguration()->getMetadataDriverImpl());
    }

    /**
     * Reads extension metadata
     *
     * @param ClassMetadata $metadata
     *
     * @return array
     */
    public function getExtensionMetadata(ClassMetadata $metadata)
    {
        if ($metadata->isMappedSuperclass) {
            return null;
        }

        $config               = [];
        $classMetadataFactory = $this->entityManager->getMetadataFactory();
        $useObjectName        = $metadata->name;

        // collect metadata from inherited classes
        if (null !== $metadata->reflClass) {
            foreach (array_reverse(class_parents($metadata->name)) as $parentClass) {
                // read only inherited mapped classes
                if ($classMetadataFactory->hasMetadataFor($parentClass)) {
                    $parentMetadata = $this->entityManager->getClassMetadata($parentClass);

                    $this->driver->readExtendedMetadata($parentMetadata, $config);

                    $isBaseInheritanceLevel = ! $parentMetadata->isInheritanceTypeNone() && ! $parentMetadata->parentClasses && $config;

                    if ($isBaseInheritanceLevel) {
                        $useObjectName = $parentMetadata->name;
                    }
                }
            }

            $this->driver->readExtendedMetadata($metadata, $config);
        }

        if ($config) {
            $config['useObjectClass'] = $useObjectName;
        }

        // cache the metadata (even if it's empty)
        // caching empty metadata will prevent re-parsing non-existent annotations
        $cacheId = self::getCacheId($metadata->name, $this->extensionNamespace);

        if ($cacheDriver = $classMetadataFactory->getCacheDriver()) {
            $cacheDriver->save($cacheId, $config, null);
        }

        return $config;
    }

    /**
     * Get the cache id
     *
     * @param string $className
     * @param string $extensionNamespace
     *
     * @return string
     */
    public static function getCacheId($className, $extensionNamespace)
    {
        return $className . '\\$' . strtoupper(str_replace('\\', '_', $extensionNamespace)) . '_CLASSMETADATA';
    }

    /**
     * Get the extended driver instance which will read the metadata required by extension
     *
     * @param MappingDriver $driver
     *
     * @throws RuntimeException if driver was not found in extension
     *
     * @return DriverInterface
     */
    protected function getDriver(MappingDriver $driver)
    {
        $extensionDriver = null;
        $driverClassName = get_class($driver);
        $driverType      = substr($driverClassName, strrpos($driverClassName, '\\') + 1);

        if ($driver instanceof MappingDriverChain || $driverType == 'DriverChain') {
            $extensionDriver = new ChainDriver();

            foreach ($driver->getDrivers() as $namespace => $chainedDriver) {
                $extensionDriver->addDriver($this->getDriver($chainedDriver), $namespace);
            }

            if (null !== $defaultDriver = $driver->getDefaultDriver() !== null) {
                $extensionDriver->setDefaultDriver($this->getDriver($defaultDriver));
            }

            return $extensionDriver;
        }

        $driverType = substr($driverType, 0, strpos($driverType, 'Driver'));

        if ($isSimplified = $this->isDriverTypeSimplified($driverType)) {
            $driverType = substr($driverType, 10);
        }

        $extensionDriverClassName = $this->extensionNamespace . '\Mapping\Driver\\' . $driverType;

        if ( ! class_exists($extensionDriverClassName)) {
            $extensionDriverClassName = $this->extensionNamespace . '\Mapping\Driver\Annotation';

            if ( ! class_exists($extensionDriverClassName)) {
                throw RuntimeException::failedAnnotationDriverFallback($extensionDriverClassName);
            }
        }

        $extensionDriver = (new $extensionDriverClassName())->setOriginalDriver($driver);

        if ($extensionDriver instanceof AbstractFileDriver) {
            if ($driver instanceof MappingDriver) {
                $extensionDriver->setLocator($driver->getLocator());
            } elseif ($isSimplified) {
                $extensionDriver->setLocator(new SymfonyFileLocator($driver->getNamespacePrefixes(), $driver->getFileExtension()));
            } else {
                $extensionDriver->setLocator(new DefaultFileLocator($driver->getPaths(), $driver->getFileExtension()));
            }
        }

        if ($extensionDriver instanceof AnnotationDriverInterface) {
            $extensionDriver->setAnnotationReader($this->annotationReader);
        }

        return $extensionDriver;
    }

    /**
     * @param string $driverType
     *
     * @return bool
     */
    private function isDriverTypeSimplified($driverType)
    {
        return substr($driverType, 0, 10) === 'Simplified';
    }
}
