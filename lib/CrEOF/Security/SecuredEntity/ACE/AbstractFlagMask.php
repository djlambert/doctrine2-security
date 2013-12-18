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

namespace CrEOF\Security\SecuredEntity\ACE;

use CrEOF\Security\Exception\InvalidArgumentException;
use CrEOF\Security\SecuredEntity\AbstractMask;
use CrEOF\Security\SecuredEntity\ACE;

/**
 * FlagMask class
 *
 * @author  Derek J. Lambert <dlambert@dereklambert.com>
 * @license http://dlambert.mit-license.org MIT
 */
class AbstractFlagMask extends AbstractMask
{
    /**
     * Constructor
     *
     * @param int $aceType
     * @param int $mask    optional
     *
     * @return AbstractFlagMask
     * @throws InvalidArgumentException
     */
    public static function create($aceType, $mask = null)
    {
        switch ($aceType) {
            case ACE::ACE_TYPE_ACCESS_ALLOWED:
                // no break
            case ACE::ACE_TYPE_ACCESS_DENIED:
                return new AccessFlagMask($mask);
            case ACE::ACE_TYPE_SYSTEM_AUDIT:
                // no break
            case ACE::ACE_TYPE_SYSTEM_ALARM:
                return new AuditFlagMask($mask);
            default:
                throw InvalidArgumentException::unsupportedAceTypeMask($aceType);
        }
    }

    /**
     * @param mixed $mask
     *
     * @return InvalidArgumentException
     */
    protected function unsupportedMask($mask)
    {
        return InvalidArgumentException::unsupportedAceFlagMask($mask);
    }

    /**
     * @param mixed $mask
     *
     * @return InvalidArgumentException
     */
    protected function maskNotInteger($mask)
    {
        return InvalidArgumentException::aceFlagMaskNotInteger($mask);
    }
}
