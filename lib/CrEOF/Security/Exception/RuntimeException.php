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
 * RuntimeException
 *
 * @author  Derek J. Lambert <dlambert@dereklambert.com>
 * @license http://dlambert.mit-license.org MIT
 */
class RuntimeException extends \RuntimeException implements ExceptionInterface
{
    /**
     * @param string $className
     *
     * @return RuntimeException
     */
    public static function eventAdapterNotFound($className)
    {
        return new self(sprintf('Event adapter class %s does not exist.', $className));
    }

    /**
     * @param string $driverClassName
     *
     * @return RuntimeException
     */
    public static function failedAnnotationDriverFallback($driverClassName)
    {
        return new self(sprintf('Failed to fallback to annotation driver %s, extension driver was not found.', $driverClassName));
    }

    /**
     * @return RuntimeException
     */
    public static function entityManagerNotSet()
    {
        return new self('getEntityManager must be called once with $eventArgs');
    }
}
