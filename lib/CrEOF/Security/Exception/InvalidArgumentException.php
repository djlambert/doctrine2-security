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
 * InvalidArgumentException
 *
 * @author  Derek J. Lambert <dlambert@dereklambert.com>
 * @license http://dlambert.mit-license.org MIT
 */
class InvalidArgumentException extends \InvalidArgumentException implements ExceptionInterface
{
    /**
     * @param int $typeMask
     *
     * @return InvalidArgumentException
     */
    public static function unsupportedAceType($typeMask)
    {
        return new self(sprintf('Unsupported ACE type 0x%08o', $typeMask));
    }

    /**
     * @param string $permission
     *
     * @return InvalidArgumentException
     */
    public static function unsupportedAcePermission($permission)
    {
        return new self(sprintf('The ACE permission "%s" is not supported', $permission));
    }

    /**
     * @param string $flag
     *
     * @return InvalidArgumentException
     */
    public static function unsupportedAceFlag($flag)
    {
        return new self(sprintf('The ACE flag "%s" is not supported', $flag));
    }

    /**
     * @return InvalidArgumentException
     */
    public static function aceTypeMaskNotInteger()
    {
        return self::valueNotInteger('ACE type mask');
    }

    /**
     * @return InvalidArgumentException
     */
    public static function acePermissionNotInteger()
    {
        return self::valueNotInteger('ACE permission');
    }

    /**
     * @return InvalidArgumentException
     */
    public static function aceFlagNotInteger()
    {
        return self::valueNotInteger('ACE flag');
    }

    /**
     * @param string $valueName
     *
     * @return InvalidArgumentException
     */
    protected static function valueNotInteger($valueName)
    {
        return new self(sprintf('% value must be an integer', $valueName));
    }
}
