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
    public static function unsupportedAceTypeMask($typeMask)
    {
        return self::unsupportedAceMask('type', sprintf('0x%08o', $typeMask));
    }

    /**
     * @param string $accessMask
     *
     * @return InvalidArgumentException
     */
    public static function unsupportedAceAccessMask($accessMask)
    {
        return self::unsupportedAceMask('access', $accessMask);
    }

    /**
     * @param string $flagMask
     *
     * @return InvalidArgumentException
     */
    public static function unsupportedAceFlagMask($flagMask)
    {
        return self::unsupportedAceMask('flag', $flagMask);
    }

    /**
     * @return InvalidArgumentException
     */
    public static function aceTypeMaskNotInteger()
    {
        return self::maskNotInteger('type');
    }

    /**
     * @return InvalidArgumentException
     */
    public static function aceAccessMaskNotInteger()
    {
        return self::maskNotInteger('access');
    }

    /**
     * @return InvalidArgumentException
     */
    public static function aceFlagMaskNotInteger()
    {
        return self::maskNotInteger('flag');
    }

    /**
     * @param string $maskName
     * @param string $mask
     *
     * @return InvalidArgumentException
     */
    protected static function unsupportedAceMask($maskName, $mask)
    {
        return new self(sprintf('ACE %s mask "%s" is not supported', $maskName, $mask));
    }

    /**
     * @param string $maskName
     *
     * @return InvalidArgumentException
     */
    protected static function maskNotInteger($maskName)
    {
        return new self(sprintf('ACE %s mask value must be an integer', $maskName));
    }
}
