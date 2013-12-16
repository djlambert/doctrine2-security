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

use CrEOF\Security\Exception\InvalidArgumentException;

/**
 * Access control entry (ACE) class
 *
 * @author  Derek J. Lambert <dlambert@dereklambert.com>
 * @license http://dlambert.mit-license.org MIT
 */
class ACE
{
    /**
     * ACE types
     */
    const ACE_TYPE_ACCESS_ALLOWED = 0x00000000;
    const ACE_TYPE_ACCESS_DENIED  = 0x00000001;
    const ACE_TYPE_SYSTEM_AUDIT   = 0x00000002;
    const ACE_TYPE_SYSTEM_ALARM   = 0x00000003;

    /**
     * ACE flags
     */
    const ACE_FLAG_INHERIT              = 0x00000001;
    const ACE_FLAG_NO_PROPAGATE_INHERIT = 0x00000004;
    const ACE_FLAG_INHERIT_ONLY         = 0x00000008;
    const ACE_FLAG_SUCCESSFUL_ACCESS    = 0x00000010;
    const ACE_FLAG_FAILED_ACCESS        = 0x00000020;
    const ACE_FLAG_IDENTIFIER_GROUP     = 0x00000040;

    /**
     * ACE masks
     */
    const ACE_MASK_VIEW             = 0b00000000000000000000000000000001; //         1,        0x1, 1 << 0
    const ACE_MASK_CREATE           = 0b00000000000000000000000000000010; //         2,        0x2, 1 << 1
    const ACE_MASK_MODIFY           = 0b00000000000000000000000000000100; //         4,        0x4, 1 << 2
    const ACE_MASK_DELETE           = 0b00000000000000000000000000001000; //         8,        0x8, 1 << 3
    const ACE_MASK_UNDELETE         = 0b00000000000000000000000000010000; //        16,       0x10, 1 << 4
    const ACE_MASK_SEARCH           = 0b00000000000000000000000000100000; //        32,       0x20, 1 << 5
    /*
    const ACE_MASK_                 = 0b00000000000000000000000001000000; //        64,       0x40, 1 << 6
    */
    const ACE_MASK_READ_ATTRIBUTES  = 0b00000000000000000000000010000000; //       128,       0x80, 1 << 7
    const ACE_MASK_WRITE_ATTRIBUTES = 0b00000000000000000000000100000000; //       256,      0x100, 1 << 8
    /*
    const ACE_MASK_                 = 0b00000000000000000000001000000000; //       512,      0x200, 1 << 9
    const ACE_MASK_                 = 0b00000000000000000000010000000000; //      1024,      0x400, 1 << 10
    const ACE_MASK_                 = 0b00000000000000000000100000000000; //      2048,      0x800, 1 << 11
    const ACE_MASK_                 = 0b00000000000000000001000000000000; //      4096,     0x1000, 1 << 12
    const ACE_MASK_                 = 0b00000000000000000010000000000000; //      8192,     0x2000, 1 << 13
    const ACE_MASK_                 = 0b00000000000000000100000000000000; //     16384,     0x4000, 1 << 14
    const ACE_MASK_                 = 0b00000000000000001000000000000000; //     32768,     0x8000, 1 << 15
    const ACE_MASK_                 = 0b00000000000000010000000000000000; //     65536,    0x10000, 1 << 16
    */
    const ACE_MASK_READ_ACL         = 0b00000000000000100000000000000000; //    131072,    0x20000, 1 << 17
    const ACE_MASK_WRITE_ACL        = 0b00000000000001000000000000000000; //    262144,    0x40000, 1 << 18
    const ACE_MASK_WRITE_OWNER      = 0b00000000000010000000000000000000; //    524288,    0x80000, 1 << 19
    /*
    const ACE_MASK_                 = 0b00000000000100000000000000000000; //   1048576,   0x100000, 1 << 20
    const ACE_MASK_                 = 0b00000000001000000000000000000000; //   2097152,   0x200000, 1 << 21
    const ACE_MASK_                 = 0b00000000010000000000000000000000; //   4194304,   0x400000, 1 << 22
    const ACE_MASK_                 = 0b00000000100000000000000000000000; //   8388608,   0x800000, 1 << 23
    const ACE_MASK_                 = 0b00000001000000000000000000000000; //  16777216,  0x1000000, 1 << 24
    const ACE_MASK_                 = 0b00000010000000000000000000000000; //  33554432,  0x2000000, 1 << 25
    const ACE_MASK_                 = 0b00000100000000000000000000000000; //  67108864,  0x4000000, 1 << 26
    const ACE_MASK_                 = 0b00001000000000000000000000000000; // 134217728,  0x8000000, 1 << 27
    const ACE_MASK_                 = 0b00010000000000000000000000000000; // 268435456, 0x10000000, 1 << 28
    */

    const ACE_MASK_FULL_CONTROL     = 0b00011111111111111111111111111111; // 536870911, 0x1FFFFFFF, 1 << 0 | 1 << 1 | ... | 1 << 28

    /**
     * @var SID
     */
    protected $sid = null;

    /**
     * @var int
     */
    protected $typeMask = 0;

    /**
     * @var int
     */
    protected $accessMask = 0;

    /**
     * @var int
     */
    protected $flagMask = 0;

    /**
     * Valid flags for access ACEs
     *
     * @var int[]
     */
    protected $accessFlags = [
        self::ACE_FLAG_INHERIT,
        self::ACE_FLAG_NO_PROPAGATE_INHERIT,
        self::ACE_FLAG_INHERIT_ONLY
    ];

    /**
     * Valid flags for audit ACEs
     *
     * @var int[]
     */
    protected $auditFlags = [
        self::ACE_FLAG_SUCCESSFUL_ACCESS,
        self::ACE_FLAG_FAILED_ACCESS
    ];

    /**
     * Type mask name lookup
     *
     * @var string[]
     */
    protected $typeConstants = [
        self::ACE_TYPE_ACCESS_ALLOWED => 'ACE_TYPE_ACCESS_ALLOWED',
        self::ACE_TYPE_ACCESS_DENIED  => 'ACE_TYPE_ACCESS_DENIED',
        self::ACE_TYPE_SYSTEM_AUDIT   => 'ACE_TYPE_SYSTEM_AUDIT',
        self::ACE_TYPE_SYSTEM_ALARM   => 'ACE_TYPE_SYSTEM_ALARM',
    ];

    /**
     * Flag mask name lookup
     *
     * @var string[]
     */
    protected $flagConstants = [
        self::ACE_FLAG_INHERIT              => 'ACE_FLAG_INHERIT',
        self::ACE_FLAG_NO_PROPAGATE_INHERIT => 'ACE_FLAG_NO_PROPAGATE_INHERIT',
        self::ACE_FLAG_INHERIT_ONLY         => 'ACE_FLAG_INHERIT_ONLY',
        self::ACE_FLAG_SUCCESSFUL_ACCESS    => 'ACE_FLAG_SUCCESSFUL_ACCESS',
        self::ACE_FLAG_FAILED_ACCESS        => 'ACE_FLAG_FAILED_ACCESS',
        self::ACE_FLAG_IDENTIFIER_GROUP     => 'ACE_FLAG_IDENTIFIER_GROUP'
    ];

    /**
     * Constructor
     *
     * @param int $typeMask optional
     *
     * @throws \InvalidArgumentException
     */
    public function __construct($typeMask = 0)
    {
        if (!is_int($typeMask)) {
            throw InvalidArgumentException::aceTypeMaskNotInteger();
        }

        if ($typeMask !== self::ACE_TYPE_ACCESS_ALLOWED && $typeMask !== self::ACE_TYPE_ACCESS_DENIED && $typeMask !== self::ACE_TYPE_SYSTEM_AUDIT && $typeMask !== self::ACE_TYPE_SYSTEM_ALARM) {
            throw InvalidArgumentException::unsupportedAceType($typeMask);
        }

        $this->typeMask = $typeMask;
    }

    /**
     * Set the accessMask
     *
     * @param mixed $permission
     *
     * @return ACE
     */
    public function setAccess($permission)
    {
        $this->accessMask = $this->getPermissionMask($permission);

        return $this;
    }

    /**
     * Adds a permission to the accessMask
     *
     * @param mixed $permission
     *
     * @return ACE
     */
    public function addAccess($permission)
    {
        $this->accessMask |= $this->getPermissionMask($permission);

        return $this;
    }

    /**
     * Removes a permission from the acccesMask
     *
     * @param mixed $permission
     *
     * @return ACE
     */
    public function removeAccess($permission)
    {
        $this->accessMask &= ~$this->getPermissionMask($permission);

        return $this;
    }

    /**
     * Returns the accessMask value
     *
     * @return int
     */
    public function getAccess()
    {
        return $this->accessMask;
    }

    /**
     * Resets the accessMask value
     *
     * @return ACE
     */
    public function resetAccess()
    {
        $this->accessMask = 0;

        return $this;
    }

    /**
     * Adds a flag to the flagMask
     *
     * @param mixed $flag
     *
     * @return ACE
     */
    public function addFlag($flag)
    {
        $this->flagMask |= $this->getFlagMask($flag);

        return $this;
    }

    /**
     * Set ACE sid
     *
     * @param mixed $sid
     * @param bool  $isGroup
     *
     * @return ACE
     */
    public function setSid($sid, $isGroup = false)
    {
        if ($sid instanceof SID) {
            $this->sid = $sid;
        } else {
            $this->sid = new SID($sid, $isGroup);
        }

        $this->flagMask &= ~self::ACE_FLAG_IDENTIFIER_GROUP;

        if ($this->sid->isGroup()) {
            $this->flagMask |= self::ACE_FLAG_IDENTIFIER_GROUP;
        }

        return $this;
    }

    /**
     * Get ACE sid
     *
     * @return SID
     */
    public function getSid()
    {
        return $this->sid;
    }

    /**
     * Get ACE type
     *
     * @return int
     */
    public function getType()
    {
        return $this->typeMask;
    }

    /**
     * Does ACE type match passed type mask?
     *
     * @param int $typeMask
     *
     * @return bool
     */
    public function isType($typeMask)
    {
        return $typeMask === ($this->typeMask & $typeMask);
    }

    /**
     * Get mask from permission value
     *
     * @param mixed $permission
     *
     * @throws \InvalidArgumentException
     *
     * @return int
     */
    private function getPermissionMask($permission)
    {
        if (is_array($permission)) {
            $permission = array_reduce($permission, function ($combined, $perm) {
                return $combined |= $this->getPermissionMask($perm);
            }, 0);
        }

        if (is_string($permission)) {
            if ( ! defined($name = sprintf('static::ACE_MASK_%s', strtoupper($permission)))) {
                throw InvalidArgumentException::unsupportedAcePermission($permission);
            }

            return constant($name);
        }

        if ( ! is_int($permission)) {
            throw InvalidArgumentException::acePermissionNotInteger();
        }

        return $permission;
    }

    /**
     * Get mask from flag value
     *
     * @param mixed $flag
     *
     * @throws \InvalidArgumentException
     *
     * @return int
     */
    private function getFlagMask($flag)
    {
        if (is_array($flag)) {
            $flag = array_reduce($flag, function ($combined, $perm) {
                return $combined |= $this->getFlagMask($perm);
            }, 0);
        }

        if (is_string($flag)) {
            if (! defined($name = sprintf('static::ACE_FLAG_%s', strtoupper($flag)))) {
                throw InvalidArgumentException::unsupportedAceFlag($flag);
            }

            $flag = constant($name);
        }

        if (! is_int($flag)) {
            throw InvalidArgumentException::aceFlagNotInteger();
        }

        if ( ! $this->isFlagValid($flag)) {
            //throw InvalidArgumentException::
        }

        return $flag;
    }

    /**
     * @param int $flag
     *
     * @return bool
     */
    private function isFlagValid($flag)
    {
        switch ($this->getType()) {
            case self::ACE_TYPE_ACCESS_ALLOWED:
                // no break
            case self::ACE_TYPE_ACCESS_DENIED:
                return in_array($flag, $this->accessFlags);

            case self::ACE_TYPE_SYSTEM_AUDIT:
                // no break
            case self::ACE_TYPE_SYSTEM_ALARM:
                return in_array($flag, $this->auditFlags);

            default:
                return false;
        }
    }
}
