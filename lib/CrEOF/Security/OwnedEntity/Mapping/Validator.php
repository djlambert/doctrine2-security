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

namespace CrEOF\Security\OwnedEntity\Mapping;

use CrEOF\Security\Exception\InvalidMappingException;
use Doctrine\ORM\Mapping\ClassMetadata;

/**
 * Mapping validator for OwnedEntity behavior
 *
 * @author  Derek J. Lambert <dlambert@dereklambert.com>
 * @license http://dlambert.mit-license.org MIT
 */
class Validator
{
    /**
     * @param ClassMetadata $metadata
     * @param array         $config
     *
     * @throws InvalidMappingException 13/864
     *
     * @return array
     */
    public function getValidatedMapping(ClassMetadata $metadata, array $config)
    {
        if ($this->isOwnedEntity($config) && ! $this->isOwnerColumnDefined($config)) {
            throw InvalidMappingException::ownerColumnNotDefined();
        }

        if ($this->isOwnerColumnDefined($config) && ! $this->isOwnedEntity($config)) {
            throw InvalidMappingException::mappingRequiresBehavior('ownerColumn');
        }

        if ( ! $this->isOwnedEntity($config)) {
            return $config;
        }

        if ( ! $this->hasOwnerColumnAssociation($metadata, $config)) {
            throw InvalidMappingException::noOwnerColumnAssociation($config['ownerColumn'], $metadata->name);
        }

        return $config;
    }

    /**
     * @param array $config
     *
     * @return bool
     */
    private function isOwnedEntity(array $config)
    {
        return isset($config['ownedEntity']) && $config['ownedEntity'] === true;
    }

    /**
     * @param array $config
     *
     * @return bool
     */
    private function isOwnerColumnDefined(array $config)
    {
        return isset($config['ownerColumn']);
    }

    /**
     * @param ClassMetadata $metadata
     * @param array         $config
     *
     * @return bool
     */
    private function isOwnerColumnMapped(ClassMetadata $metadata, array $config)
    {
        return $metadata->hasField($config['ownerColumn']);
    }

    /**
     * @param ClassMetadata $metadata
     * @param array         $config
     *
     * @return bool
     */
    private function hasOwnerColumnAssociation(ClassMetadata $metadata, array $config)
    {
        return $metadata->hasAssociation($config['ownerColumn']);
    }
}
