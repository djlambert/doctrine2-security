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

use CrEOF\Security\Tool\WrapperInterface;
use Doctrine\ORM\EntityManager;

/**
 * Wraps entity or proxy for more convenient manipulation
 *
 * @author  Derek J. Lambert <dlambert@dereklambert.com>
 * @license http://dlambert.mit-license.org MIT
 */
abstract class AbstractWrapper implements WrapperInterface
{
    /**
     * Object metadata
     *
     * @var object
     */
    protected $metadata;

    /**
     * Wrapped object
     *
     * @var object
     */
    protected $object;

    /**
     * @var EntityManager
     */
    protected $entityManager;

    /**
     * List of wrapped object references
     *
     * @var array
     */
    private static $wrappedObjectReferences;

    /**
     * {@inheritDoc}
     */
    public function getObject()
    {
        return $this->object;
    }

    /**
     * {@inheritDoc}
     */
    public function getMetadata()
    {
        return $this->metadata;
    }

    /**
     * {@inheritDoc}
     */
    public function populate(array $data)
    {
        foreach ($data as $field => $value) {
            $this->setPropertyValue($field, $value);
        }

        return $this;
    }

    /**
     * Wrap object factory method
     *
     * @param object        $object
     * @param EntityManager $entityManager
     *
     * @return WrapperInterface
     */
    public static function wrap($object, EntityManager $entityManager)
    {
        $oid = spl_object_hash($object);

        if (!isset(self::$wrappedObjectReferences[$oid])) {
            self::$wrappedObjectReferences[$oid] = new EntityWrapper($object, $entityManager);
        }

        return self::$wrappedObjectReferences[$oid];
    }

    /**
     *
     */
    public static function clear()
    {
        self::$wrappedObjectReferences = [];
    }
}
