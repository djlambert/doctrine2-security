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

namespace CrEOF\Security\Tool;

/**
 * Object wrapper interface
 *
 * @author  Derek J. Lambert <dlambert@dereklambert.com>
 * @license http://dlambert.mit-license.org MIT
 */
interface WrapperInterface
{
    /**
     * Get currently wrapped object
     *
     * @return object
     */
    function getObject();

    /**
     * Extract property value from object
     *
     * @param string $property
     *
     * @return mixed
     */
    function getPropertyValue($property);

    /**
     * Set the property
     *
     * @param string $property
     * @param mixed  $value
     *
     * @return WrapperInterface
     */
    function setPropertyValue($property, $value);

    /**
     * Populates the object with given property values
     *
     * @param array $data
     *
     * @return WrapperInterface
     */
    function populate(array $data);

    /**
     * Checks if identifier is valid
     *
     * @return boolean
     */
    function hasValidIdentifier();

    /**
     * Get metadata
     *
     * @return object
     */
    function getMetadata();

    /**
     * Get the object identifier, $single or composite
     *
     * @param boolean $single optional
     *
     * @return array|mixed
     */
    function getIdentifier($single = true);

    /**
     * Get root object class name
     *
     * @return string
     */
    function getRootObjectName();
}
