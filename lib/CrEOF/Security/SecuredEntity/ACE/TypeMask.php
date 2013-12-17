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
use CrEOF\Security\SecuredEntity\AbstractSimpleMask;
use CrEOF\Security\SecuredEntity\ACE;

/**
 * TypeMask class
 *
 * @author  Derek J. Lambert <dlambert@dereklambert.com>
 * @license http://dlambert.mit-license.org MIT
 */
class TypeMask extends AbstractSimpleMask
{
    /**
     * Type mask name lookup
     *
     * @var array
     */
    protected $lookupConstants = [
        ACE::ACE_TYPE_ACCESS_ALLOWED => 'ACE_TYPE_ACCESS_ALLOWED',
        ACE::ACE_TYPE_ACCESS_DENIED  => 'ACE_TYPE_ACCESS_DENIED',
        ACE::ACE_TYPE_SYSTEM_AUDIT   => 'ACE_TYPE_SYSTEM_AUDIT',
        ACE::ACE_TYPE_SYSTEM_ALARM   => 'ACE_TYPE_SYSTEM_ALARM',
    ];

    /**
     * Type mask token value lookup
     *
     * Tokens with underscores removed included for camelCase support
     *
     * @var array
     */
    protected $tokenConstants = [
        'ACCESS_ALLOWED' => ACE::ACE_TYPE_ACCESS_ALLOWED,
        'ACCESSALLOWED'  => ACE::ACE_TYPE_ACCESS_ALLOWED,
        'ALLOWED'        => ACE::ACE_TYPE_ACCESS_ALLOWED,
        'ALLOW'          => ACE::ACE_TYPE_ACCESS_ALLOWED,
        'ACCESS_DENIED'  => ACE::ACE_TYPE_ACCESS_DENIED,
        'ACCESSDENIED'   => ACE::ACE_TYPE_ACCESS_DENIED,
        'DENIED'         => ACE::ACE_TYPE_ACCESS_DENIED,
        'DENY'           => ACE::ACE_TYPE_ACCESS_DENIED,
        'SYSTEM_AUDIT'   => ACE::ACE_TYPE_SYSTEM_AUDIT,
        'SYSTEMAUDIT'    => ACE::ACE_TYPE_SYSTEM_AUDIT,
        'AUDIT'          => ACE::ACE_TYPE_SYSTEM_AUDIT,
        'SYSTEM_ALARM'   => ACE::ACE_TYPE_SYSTEM_ALARM,
        'SYSTEMALARM'    => ACE::ACE_TYPE_SYSTEM_ALARM,
        'ALARM'          => ACE::ACE_TYPE_SYSTEM_ALARM
    ];

    /**
     * @param int $mask
     *
     * @return bool
     */
    protected function isValid($mask)
    {
        return isset($this->lookupConstants[$mask]);
    }

    /**
     * @param mixed $mask
     *
     * @return InvalidArgumentException
     */
    protected function unsupportedMask($mask)
    {
        return InvalidArgumentException::unsupportedAceTypeMask($mask);
    }

    /**
     * @param mixed $mask
     *
     * @return InvalidArgumentException
     */
    protected function maskNotInteger($mask)
    {
        return InvalidArgumentException::aceTypeMaskNotInteger($mask);
    }
}
