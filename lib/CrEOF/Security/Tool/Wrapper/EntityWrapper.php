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

namespace CrEOF\Security\Tool\Wrapper;

use Doctrine\ORM\EntityManager;
use Doctrine\ORM\Proxy\Proxy;

/**
 * Wraps entity or proxy for more convenient manipulation
 *
 * @author  Derek J. Lambert <dlambert@dereklambert.com>
 * @license http://dlambert.mit-license.org MIT
 */
class EntityWrapper extends AbstractWrapper
{
    /**
     * Entity identifier
     *
     * @var array
     */
    private $identifier;

    /**
     * True if entity or proxy is loaded
     *
     * @var boolean
     */
    private $initialized = false;

    /**
     * Wrap entity
     *
     * @param object        $entity
     * @param EntityManager $entityManager
     */
    public function __construct($entity, EntityManager $entityManager)
    {
        $this->entityManager = $entityManager;
        $this->object        = $entity;
        $this->metadata      = $entityManager->getClassMetadata(get_class($this->object));
    }

    /**
     * {@inheritDoc}
     */
    public function getPropertyValue($property)
    {
        $this->initialize();

        return $this->metadata->getReflectionProperty($property)->getValue($this->object);
    }

    /**
     * {@inheritDoc}
     */
    public function setPropertyValue($property, $value)
    {
        $this->initialize();
        $this->metadata->getReflectionProperty($property)->setValue($this->object, $value);

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function hasValidIdentifier()
    {
        return (null !== $this->getIdentifier());
    }

    /**
     * {@inheritDoc}
     */
    public function getRootObjectName()
    {
        return $this->metadata->rootEntityName;
    }

    /**
     * {@inheritDoc}
     */
    public function getIdentifier($single = true)
    {
        if (null === $this->identifier) {
            if ($this->object instanceof Proxy) {
                $uow = $this->entityManager->getUnitOfWork();

                if ($uow->isInIdentityMap($this->object)) {
                    $this->identifier = $uow->getEntityIdentifier($this->object);
                } else {
                    $this->initialize();
                }
            }
            if (null === $this->identifier) {
                $this->identifier = [];
                $incomplete = false;

                foreach ($this->metadata->identifier as $name) {
                    $this->identifier[$name] = $this->getPropertyValue($name);

                    if (null === $this->identifier[$name]) {
                        $incomplete = true;
                    }
                }

                if ($incomplete) {
                    $this->identifier = null;
                }
            }
        }

        if ($single && is_array($this->identifier)) {
            return reset($this->identifier);
        }

        return $this->identifier;
    }

    /**
     * Initialize the entity if it is proxy
     * required when is detached or not initialized
     */
    protected function initialize()
    {
        if (!$this->initialized) {
            if ($this->object instanceof Proxy) {
                $uow = $this->entityManager->getUnitOfWork();

                if (!$this->object->__isInitialized__) {
                    $this->object->__load();
                }
            }
        }
    }
}
