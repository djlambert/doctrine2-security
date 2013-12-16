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

namespace CrEOF\Security\SecuredEntity;

/**
 * Security identifier (SID) class
 *
 * @author  Derek J. Lambert <dlambert@dereklambert.com>
 * @license http://dlambert.mit-license.org MIT
 */
class SID
{
    /**
     * SID type masks
     */
    const SID_TYPE_SPECIAL = 0x00000001;
    const SID_TYPE_GROUP   = 0x00000002;

    /**
     * SID special identifiers
     */
    const SID_WHO_OWNER         = 'OWNER';
    const SID_WHO_GROUP         = 'GROUP';
    const SID_WHO_EVERYONE      = 'EVERYONE';
    const SID_WHO_INTERACTIVE   = 'INTERACTIVE';
    const SID_WHO_NETWORK       = 'NETWORK';
    const SID_WHO_DIALUP        = 'DIALUP';
    const SID_WHO_BATCH         = 'BATCH';
    const SID_WHO_ANONYMOUS     = 'ANONYMOUS';
    const SID_WHO_AUTHENTICATED = 'AUTHENTICATED';
    const SID_WHO_SERVICE       = 'SERVICE';

    /**
     * @var mixed
     */
    protected $sid = null;

    /**
     * @var int
     */
    protected $typeMask = 0;

    /**
     * Constructor
     *
     * @param mixed $sid
     * @param bool  $isGroup optional
     *
     * @throws \InvalidArgumentException
     */
    public function __construct($sid = null, $isGroup = false)
    {
        if (null !== $sid) {
            $this->set($sid, $isGroup);
        }
    }

    /**
     * Set SID value
     *
     * @param mixed $sid
     * @param bool  $isGroup optional
     *
     * @return ACE
     */
    public function set($sid, $isGroup = false)
    {
        $typeMask = 0;

        if ($this->isSidSpecial($sid)) {
            $isGroup = false;
            $typeMask |= self::SID_TYPE_SPECIAL;
        }

        if ($isGroup) {
            $typeMask |= self::SID_TYPE_GROUP;
        }

        $this->typeMask = $typeMask;
        $this->sid      = $sid;

        return $this;
    }

    /**
     * Get SID value
     *
     * @return mixed
     */
    public function get()
    {
        return $this->sid;
    }

    /**
     * Is group SID?
     *
     * @return bool
     */
    public function isGroup()
    {
        return self::SID_TYPE_GROUP === ($this->typeMask & self::SID_TYPE_GROUP);
    }

    /**
     * Is special SID?
     *
     * @return bool
     */
    public function isSpecial()
    {
        return self::SID_TYPE_SPECIAL === ($this->typeMask & self::SID_TYPE_SPECIAL);
    }

    /**
     * Check if SID is a special identifier
     *
     * @param string &$sid if special SID value is normalized
     *
     * @return bool
     */
    protected function isSidSpecial(&$sid)
    {
        $localSid = strtoupper(preg_replace('/^([^@]+)@$/', '$1', $sid));

        if (is_string($sid) && defined('static::SID_WHO_' . $localSid)) {
            $sid = $localSid . '@';

            return true;
        }

        return false;
    }
}
