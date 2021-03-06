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

use CrEOF\Security\SecuredEntity\ACE;

/**
 * AuditFlagMask class
 *
 * @author  Derek J. Lambert <dlambert@dereklambert.com>
 * @license http://dlambert.mit-license.org MIT
 */
class AuditFlagMask extends AbstractFlagMask
{
    /**
     * Audit flag mask name lookup
     *
     * @var array
     */
    protected $lookupConstants = [
        ACE::ACE_FLAG_SUCCESSFUL_ACCESS    => 'ACE_FLAG_SUCCESSFUL_ACCESS',
        ACE::ACE_FLAG_FAILED_ACCESS        => 'ACE_FLAG_FAILED_ACCESS',
    ];

    /**
     * Audit flag mask token value lookup
     *
     * Tokens with underscores removed included for camelCase support
     *
     * @var array
     */
    protected $tokenConstants = [
        'SUCCESSFUL_ACCESS'    => ACE::ACE_FLAG_SUCCESSFUL_ACCESS,
        'SUCCESSFULACCESS'     => ACE::ACE_FLAG_SUCCESSFUL_ACCESS,
        'SUCCESSFUL'           => ACE::ACE_FLAG_SUCCESSFUL_ACCESS,
        'FAILED_ACCESS'        => ACE::ACE_FLAG_FAILED_ACCESS,
        'FAILEDACCESS'         => ACE::ACE_FLAG_FAILED_ACCESS,
        'FAILED'               => ACE::ACE_FLAG_FAILED_ACCESS,
    ];
}
