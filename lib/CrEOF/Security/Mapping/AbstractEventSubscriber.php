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
use Doctrine\Common\Annotations\AnnotationReader;
use Doctrine\Common\Annotations\AnnotationRegistry;
use Doctrine\Common\Annotations\CachedReader;
use Doctrine\Common\Annotations\Reader;
use Doctrine\Common\Cache\ArrayCache;
use Doctrine\Common\EventSubscriber;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\Event\LifecycleEventArgs;
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
     * @param LifecycleEventArgs $eventArgs optional
     *
     * @throws RuntimeException
     *
     * @return EntityManager
     */
    public function getEntityManager(LifecycleEventArgs $eventArgs = null)
    {
        if (null !== $this->entityManager) {
            return $this->entityManager;
        }

        if (null === $eventArgs) {
            throw RuntimeException::entityManagerNotSet();
        }

        return $this->entityManager = $eventArgs->getEntityManager();
    }

    /**
     * Maps additional metadata for the entity
     *
     * @param LoadClassMetadataEventArgs $eventArgs
     */
    public function loadClassMetadata(LoadClassMetadataEventArgs $eventArgs)
    {
        $this->loadMetadataForObjectClass($eventArgs->getClassMetadata(), $eventArgs);
    }

    /**
     * Get namespace of event subscriber
     *
     * @return string
     */
    abstract protected function getNamespace();

    /**
     * Scans metadata for behavior mappings
     *
     * @param ClassMetadata              $metadata
     * @param LoadClassMetadataEventArgs $eventArgs optional
     */
    protected function loadMetadataForObjectClass(ClassMetadata $metadata, LoadClassMetadataEventArgs $eventArgs = null)
    {
        if (null !== $eventArgs && null === $this->entityManager) {
            $this->entityManager = $eventArgs->getEntityManager();
        }

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
