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

namespace CrEOF\Security;

use CrEOF\Security\Exception\RuntimeException;
use CrEOF\Security\Mapping\ExtensionMetadataFactory;
use Doctrine\Common\Annotations\AnnotationReader;
use Doctrine\Common\Annotations\AnnotationRegistry;
use Doctrine\Common\Annotations\CachedReader;
use Doctrine\Common\Annotations\Reader;
use Doctrine\Common\Cache\ArrayCache;
use Doctrine\Common\EventSubscriber;
use Doctrine\Common\NotifyPropertyChanged;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\Event\LoadClassMetadataEventArgs;
use Doctrine\ORM\Mapping\ClassMetadata;

/**
 * Event subscriber class extension for handling of extension metadata mapping
 *
 * @author  Derek J. Lambert <dlambert@dereklambert.com>
 * @license http://dlambert.mit-license.org MIT
 */
abstract class AbstractEventSubscriber implements EventSubscriber
{
    /**
     * Static array of cached object configurations
     *
     * @var array
     */
    protected static $configurations = [];

    /**
     * @var string
     */
    protected $listenerName;

    /**
     * @var AnnotationReader
     */
    private static $defaultAnnotationReader;

    /**
     * Custom annotation reader
     *
     * @var Reader
     */
    private $annotationReader;

    /**
     * @var EntityManager
     */
    private $entityManager;

    /**
     * @var ExtensionMetadataFactory
     */
    private $extensionMetadataFactory = [];

    /**
     * Constructor
     */
    public function __construct()
    {
        $namespaceParts     = explode('\\', $this->getNamespace());
        $this->listenerName = end($namespaceParts);
    }

    /**
     * Specifies the list of events to listen for
     *
     * @return array
     */
    public function getSubscribedEvents()
    {
        return [
            'loadClassMetadata'
        ];
    }

    /**
     * Maps additional metadata for the entity
     *
     * @param LoadClassMetadataEventArgs $eventArgs
     */
    public function loadClassMetadata(LoadClassMetadataEventArgs $eventArgs)
    {
        $this->setEntityManager($eventArgs->getEntityManager())
            ->loadMetadataForObjectClass($eventArgs->getClassMetadata());
    }

    /**
     * Get the configuration for specific object class
     * if cache driver is present it scans it also
     *
     * @param string $className
     *
     * @return array
     */
    public function getConfiguration($className, EntityManager $entityManager = null)
    {
        $config = [];

        if (isset(self::$configurations[$this->listenerName][$className])) {
            return self::$configurations[$this->listenerName][$className];
        }

        $entityManager = $entityManager ?: $this->getEntityManager();
        $factory       = $entityManager->getMetadataFactory();
        $cacheDriver   = $factory->getCacheDriver();

        if ($cacheDriver) {
            $cacheId = ExtensionMetadataFactory::getCacheId($className, $this->getNamespace());

            if (false !== ($cached = $cacheDriver->fetch($cacheId))) {
                $config = self::$configurations[$this->listenerName][$className] = $cached;
            } else {
                $this->loadMetadataForObjectClass($factory->getMetadataFor($className));

                if (isset(self::$configurations[$this->listenerName][$className])) {
                    $config = self::$configurations[$this->listenerName][$className];
                }
            }

            $objectClass = isset($config['useObjectClass']) ? $config['useObjectClass'] : $className;

            if ($objectClass !== $className) {
                $this->getConfiguration($entityManager, $objectClass);
            }

        }

        return $config;
    }

    /**
     * Get namespace of event subscriber
     *
     * @return string
     */
    abstract protected function getNamespace();

    /**
     * Update field value using reflection
     *
     * @param ClassMetadata $metadata
     * @param object        $entity
     * @param string        $field
     * @param mixed         $value
     */
    protected function updateField(ClassMetadata $metadata, $entity, $field, $value)
    {
        $property = $metadata->getReflectionProperty($field);
        $oldValue = $property->getValue($entity);

        $property->setValue($entity, $value);

        if ($entity instanceof NotifyPropertyChanged) {
            $unitOfWork = $this->getEntityManager()->getUnitOfWork();

            $unitOfWork->propertyChanged($entity, $field, $oldValue, $value);
        }
    }

    /**
     * @throws RuntimeException
     *
     * @return EntityManager
     */
    protected function getEntityManager()
    {
        if (null !== $this->entityManager) {
            return $this->entityManager;
        }

        throw RuntimeException::entityManagerNotSet();
    }

    /**
     * @param EntityManager $entityManager
     *
     * @return AbstractEventSubscriber
     */
    protected function setEntityManager(EntityManager $entityManager)
    {
        $this->entityManager = $entityManager;

        return $this;
    }

    /**
     * Scans metadata for behavior mappings
     *
     * @param ClassMetadata $metadata
     */
    protected function loadMetadataForObjectClass(ClassMetadata $metadata)
    {
        try {
            $config = $this->getExtensionMetadataFactory()->getExtensionMetadata($metadata);
        } catch (\ReflectionException $e) {
            // entity generator is running, will not store a cached version, to remap later
            $config = false;
        }

        if ($config) {
            self::$configurations[$this->listenerName][$metadata->name] = $config;
        }
    }

    /**
     * Get extension metadata mapping reader
     *
     * @return ExtensionMetadataFactory
     */
    private function getExtensionMetadataFactory()
    {
        $oid = spl_object_hash($entityManager = $this->getEntityManager());

        if (isset($this->extensionMetadataFactory[$oid])) {
            return $this->extensionMetadataFactory[$oid];
        }

        if (null === $this->annotationReader) {
            $this->annotationReader = $this->getDefaultAnnotationReader();
        }

        return $this->extensionMetadataFactory[$oid] = new ExtensionMetadataFactory($entityManager, $this->getNamespace(), $this->annotationReader);
    }

    /**
     * Create default annotation reader for extensions
     *
     * @return CachedReader
     */
    private function getDefaultAnnotationReader()
    {
        if (null !== self::$defaultAnnotationReader) {
            return self::$defaultAnnotationReader;
        }

        AnnotationRegistry::registerAutoloadNamespace('CrEOF\\Security\\Mapping\\Annotation', __DIR__ . '/../../../');

        return self::$defaultAnnotationReader = new CachedReader(new AnnotationReader(), new ArrayCache());
    }
}
