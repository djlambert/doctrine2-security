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

namespace CrEOF\Security\OwnedEntity\Mapping\Driver;

use CrEOF\Security\Mapping\Driver\AbstractAnnotationDriver;
use CrEOF\Security\OwnedEntity\Mapping\Validator;
use Doctrine\ORM\Mapping\ClassMetadata;

/**
 * Annotation mapping driver for OwnedEntity behavior extension
 *
 * @author  Derek J. Lambert <dlambert@dereklambert.com>
 * @license http://dlambert.mit-license.org MIT
 */
class Annotation extends AbstractAnnotationDriver
{
    /**
     * Annotated class is an OwnedEntity
     */
    const OWNED_ENTITY = 'CrEOF\\Security\\Mapping\\Annotation\\OwnedEntity';

    /**
     * Annotated property is owner association
     */
    const OWNER_COLUMN = 'CrEOF\\Security\\Mapping\\Annotation\\OwnerColumn';

    /**
     * {@inheritDoc}
     */
    public function readExtendedMetadata(ClassMetadata $metadata, array &$config)
    {
        $classRefl = $metadata->getReflectionClass();

        if ($annotation = $this->reader->getClassAnnotation($classRefl, self::OWNED_ENTITY)) {
            $config['ownedEntity'] = true;

            if ($entityListenerClass = $annotation->entityListenerClass) {
                $config['ownedEntityListenerClass'] = $entityListenerClass;
            }
        }

        foreach ($classRefl->getProperties() as $property) {
            if ($metadata->isMappedSuperclass && ! $property->isPrivate() || $metadata->isInheritedField($property->name) || isset($metadata->associationMappings[$property->name]['inherited'])) {
                continue;
            }

            if ($this->reader->getPropertyAnnotation($property, self::OWNER_COLUMN)) {
                $config['ownerColumn'] = $property->getName();
            }
        }

        (new Validator())->validateMapping($metadata, $config);
    }
}
