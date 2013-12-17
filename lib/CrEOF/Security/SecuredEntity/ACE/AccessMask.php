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
 * AccessMask class
 *
 * @author  Derek J. Lambert <dlambert@dereklambert.com>
 * @license http://dlambert.mit-license.org MIT
 */
class AccessMask extends AbstractMask
{
    /**
     * Access mask name lookup
     *
     * @var array
     */
//    protected $lookupConstants = [
//        ACE::ACE_MASK_VIEW             => 'ACE_MASK_VIEW',
//        ACE::ACE_MASK_CREATE           => 'ACE_MASK_CREATE',
//        ACE::ACE_MASK_MODIFY           => 'ACE_MASK_MODIFY',
//        ACE::ACE_MASK_DELETE           => 'ACE_MASK_DELETE',
//        ACE::ACE_MASK_UNDELETE         => 'ACE_MASK_UNDELETE',
//        ACE::ACE_MASK_SEARCH           => 'ACE_MASK_SEARCH',
//        ACE::ACE_MASK_READ_ATTRIBUTES  => 'ACE_MASK_READ_ATTRIBUTES',
//        ACE::ACE_MASK_WRITE_ATTRIBUTES => 'ACE_MASK_WRITE_ATTRIBUTES',
//        ACE::ACE_MASK_READ_ACL         => 'ACE_MASK_READ_ACL',
//        ACE::ACE_MASK_WRITE_ACL        => 'ACE_MASK_WRITE_ACL',
//        ACE::ACE_MASK_WRITE_OWNER      => 'ACE_MASK_WRITE_OWNER',
//        ACE::ACE_MASK_FULL_CONTROL     => 'ACE_MASK_FULL_CONTROL'
//    ];

    /**
     * Access mask token value lookup
     *
     * Tokens with underscores removed included for camelCase support
     *
     * @var array
     */
    protected $tokenConstants = [
        'VIEW'             => ACE::ACE_MASK_VIEW,
        'CREATE'           => ACE::ACE_MASK_CREATE,
        'MODIFY'           => ACE::ACE_MASK_MODIFY,
        'DELETE'           => ACE::ACE_MASK_DELETE,
        'UNDELETE'         => ACE::ACE_MASK_UNDELETE,
        'SEARCH'           => ACE::ACE_MASK_SEARCH,
        'READ_ATTRIBUTES'  => ACE::ACE_MASK_READ_ATTRIBUTES,
        'READATTRIBUTES'   => ACE::ACE_MASK_READ_ATTRIBUTES,
        'WRITE_ATTRIBUTES' => ACE::ACE_MASK_WRITE_ATTRIBUTES,
        'WRITEATTRIBUTES'  => ACE::ACE_MASK_WRITE_ATTRIBUTES,
        'READ_ACL'         => ACE::ACE_MASK_READ_ACL,
        'READACL'          => ACE::ACE_MASK_READ_ACL,
        'WRITE_ACL'        => ACE::ACE_MASK_WRITE_ACL,
        'WRITEACL'         => ACE::ACE_MASK_WRITE_ACL,
        'WRITE_OWNER'      => ACE::ACE_MASK_WRITE_OWNER,
        'WRITEOWNER'       => ACE::ACE_MASK_WRITE_OWNER,
        'FULL_CONTROL'     => ACE::ACE_MASK_FULL_CONTROL,
        'FULLCONTROL'      => ACE::ACE_MASK_FULL_CONTROL
    ];

    /**
     * @param int $mask
     *
     * @return bool
     */
    protected function isValid($mask)
    {
        return $mask === (ACE::ACE_MASK_FULL_CONTROL & $mask);
    }

    /**
     * @param mixed $mask
     *
     * @return InvalidArgumentException
     */
    protected function unsupportedMask($mask)
    {
        return InvalidArgumentException::unsupportedAceAccessMask($mask);
    }

    /**
     * @param mixed $mask
     *
     * @return InvalidArgumentException
     */
    protected function maskNotInteger($mask)
    {
        return InvalidArgumentException::aceAccessMaskNotInteger($mask);
    }
}
