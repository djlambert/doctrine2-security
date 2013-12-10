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

namespace CrEOF\Security\Exception;

use CrEOF\Security\ExceptionInterface;

/**
 * InvalidMappingException
 *
 * @author  Derek J. Lambert <dlambert@dereklambert.com>
 * @license http://dlambert.mit-license.org MIT
 */
class InvalidMappingException extends InvalidArgumentException implements ExceptionInterface
{
    /**
     * @return InvalidMappingException
     */
    public static function ownerColumnNotDefined()
    {
        return new self('OwnedEntity behavior requires OwnerColumn mapping');
    }

    /**
     * @param string $mapping
     *
     * @return InvalidMappingException
     */
    public static function mappingRequiresBehavior($mapping)
    {
        return new self(sprintf('%s mapping requires OwnedEntity behavior', $mapping));
    }

    /**
     * @param string $ownedEntityListenerClass
     *
     * @return InvalidMappingException
     */
    public static function ownedEntityListenerNotExist($ownedEntityListenerClass)
    {
        return new self(sprintf('OwnedEntity listener class "%s" does not exist', $ownedEntityListenerClass));
    }

    /**
     * @param string $ownedEntityListenerClass
     *
     * @return InvalidMappingException
     */
    public static function listenerInterfaceNotImplemented($ownedEntityListenerClass)
    {
        return new self(sprintf('OwnedEntity listener class "%s" does not implement EntityListenerInterface', $ownedEntityListenerClass));
    }

    /**
     * @param string $attributeName
     * @param string $rawValue
     *
     * @return InvalidMappingException
     */
    public static function attributeValueNotBoolean($attributeName, $rawValue)
    {
        return new self(sprintf("Attribute %s must have a valid boolean value, '%s' found", $attributeName, $rawValue));
    }
}
