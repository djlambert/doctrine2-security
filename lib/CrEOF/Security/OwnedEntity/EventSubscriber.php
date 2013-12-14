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

namespace CrEOF\Security\OwnedEntity;

use CrEOF\Security\AbstractEventSubscriber;
use Doctrine\ORM\Event\LifecycleEventArgs;

/**
 * Class OwnedEntity event subscriber
 *
 * @author  Derek J. Lambert <dlambert@dereklambert.com>
 * @license http://dlambert.mit-license.org MIT
 */
class EventSubscriber extends AbstractEventSubscriber
{
    /**
     * @var object
     */
    protected $owner;

    /**
     * Specifies the list of events to listen for
     *
     * @return array
     */
    public function getSubscribedEvents()
    {
        return [
            'loadClassMetadata',
            'prePersist'
        ];
    }

    /**
     * @param LifecycleEventArgs $args
     */
    public function prePersist(LifecycleEventArgs $args)
    {
        $entityManager = $this->getEntityManager();
        $entity        = $args->getEntity();
        $metadata      = $entityManager->getClassMetadata(get_class($entity));

        if ( ! $config = $this->getConfiguration($metadata->getName())) {
            return;
        }

        if (isset($config['ownedEntity'])) {
            if ($metadata->getReflectionProperty($field = $config['ownerColumn'])->getValue($entity) === null) {
                $this->updateField($metadata, $entity, $field, $this->getOwner());
            }
        }
    }

    /**
     * @param object $owner
     *
     * @return EventSubscriber
     */
    public function setOwner($owner)
    {
        $this->owner = $owner;

        return $this;
    }

    /**
     * @return object
     */
    public function getOwner()
    {
        return $this->owner;
    }

    /**
     * {@inheritDoc}
     */
    protected function getNamespace()
    {
        return __NAMESPACE__;
    }
}
