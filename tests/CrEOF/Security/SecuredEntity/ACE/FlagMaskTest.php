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
use CrEOF\Security\SecuredEntity\ACE;
use CrEOF\Security\SecuredEntity\ACE\AbstractFlagMask;

/**
 * FlagMask test
 *
 * @author  Derek J. Lambert <dlambert@dereklambert.com>
 * @license http://dlambert.mit-license.org MIT
 */
class FlagMaskTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @param int   $type
     * @param array $add
     * @param array $remove
     * @param int   $expected
     *
     * @test
     * @dataProvider aceFlagMaskMultiValueData
     */
    public function aceFlagMaskTest($type, $add, $remove, $expected)
    {
        $flag = AbstractFlagMask::create($type);

        foreach ($add as $mask) {
            $flag->add($mask);
        }

        foreach ($remove as $mask) {
            $flag->remove($mask);
        }

        $this->assertEquals($expected, $flag->get());
    }

    /**
     * @param int   $type
     * @param mixed $mask
     * @param int   $expected
     *
     * @test
     * @dataProvider aceFlagMaskSimpleValidData
     */
    public function aceFlagMaskValidTypeTest($type, $mask, $expected)
    {
        $flag = AbstractFlagMask::create($type, $mask);

        $this->assertEquals($expected, $flag->get());
    }

    /**
     * @param int   $type
     * @param mixed $mask
     *
     * @test
     * @dataProvider aceFlagMaskInvalidTypeData
     * @expectedException InvalidArgumentException
     */
    public function aceFlagMaskInvalidTypeTest($type, $mask)
    {
        AbstractFlagMask::create($type, $mask);
    }

    /**
     * @return array[]
     */
    public function aceFlagMaskSimpleValidData()
    {
        return [
            [ACE::ACE_TYPE_ACCESS_ALLOWED, ACE::ACE_FLAG_INHERIT, ACE::ACE_FLAG_INHERIT],
            [ACE::ACE_TYPE_ACCESS_ALLOWED, ACE::ACE_FLAG_NO_PROPAGATE_INHERIT, ACE::ACE_FLAG_NO_PROPAGATE_INHERIT],
            [ACE::ACE_TYPE_ACCESS_ALLOWED, ACE::ACE_FLAG_INHERIT_ONLY, ACE::ACE_FLAG_INHERIT_ONLY],
            [ACE::ACE_TYPE_ACCESS_DENIED, ACE::ACE_FLAG_INHERIT, ACE::ACE_FLAG_INHERIT],
            [ACE::ACE_TYPE_ACCESS_DENIED, ACE::ACE_FLAG_NO_PROPAGATE_INHERIT, ACE::ACE_FLAG_NO_PROPAGATE_INHERIT],
            [ACE::ACE_TYPE_ACCESS_DENIED, ACE::ACE_FLAG_INHERIT_ONLY, ACE::ACE_FLAG_INHERIT_ONLY],
            [ACE::ACE_TYPE_ACCESS_ALLOWED, 'inherit', ACE::ACE_FLAG_INHERIT],
            [ACE::ACE_TYPE_ACCESS_DENIED, 'inherit', ACE::ACE_FLAG_INHERIT],
            [ACE::ACE_TYPE_ACCESS_ALLOWED, 'no_pRopaGate_iNherit', ACE::ACE_FLAG_NO_PROPAGATE_INHERIT],
            [ACE::ACE_TYPE_ACCESS_ALLOWED, 'noPropagateInherit', ACE::ACE_FLAG_NO_PROPAGATE_INHERIT],
            [ACE::ACE_TYPE_ACCESS_DENIED, 'no_pRopaGate_iNherit', ACE::ACE_FLAG_NO_PROPAGATE_INHERIT],
            [ACE::ACE_TYPE_ACCESS_DENIED, 'noPropagateInherit', ACE::ACE_FLAG_NO_PROPAGATE_INHERIT],
            [ACE::ACE_TYPE_ACCESS_ALLOWED, 'iNherIt_onlY', ACE::ACE_FLAG_INHERIT_ONLY],
            [ACE::ACE_TYPE_ACCESS_ALLOWED, 'inheritOnly', ACE::ACE_FLAG_INHERIT_ONLY],
            [ACE::ACE_TYPE_ACCESS_DENIED, 'iNherIt_onlY', ACE::ACE_FLAG_INHERIT_ONLY],
            [ACE::ACE_TYPE_ACCESS_DENIED, 'inheritOnly', ACE::ACE_FLAG_INHERIT_ONLY],
            [ACE::ACE_TYPE_SYSTEM_AUDIT, ACE::ACE_FLAG_SUCCESSFUL_ACCESS, ACE::ACE_FLAG_SUCCESSFUL_ACCESS],
            [ACE::ACE_TYPE_SYSTEM_AUDIT, ACE::ACE_FLAG_FAILED_ACCESS, ACE::ACE_FLAG_FAILED_ACCESS],
            [ACE::ACE_TYPE_SYSTEM_ALARM, ACE::ACE_FLAG_SUCCESSFUL_ACCESS, ACE::ACE_FLAG_SUCCESSFUL_ACCESS],
            [ACE::ACE_TYPE_SYSTEM_ALARM, ACE::ACE_FLAG_FAILED_ACCESS, ACE::ACE_FLAG_FAILED_ACCESS],
            [ACE::ACE_TYPE_SYSTEM_AUDIT, 'SUCCESSFUL_aCCESS', ACE::ACE_FLAG_SUCCESSFUL_ACCESS],
            [ACE::ACE_TYPE_SYSTEM_AUDIT, 'successfulAccess', ACE::ACE_FLAG_SUCCESSFUL_ACCESS],
            [ACE::ACE_TYPE_SYSTEM_AUDIT, 'suCCeSSful', ACE::ACE_FLAG_SUCCESSFUL_ACCESS],
            [ACE::ACE_TYPE_SYSTEM_ALARM, 'SUCCESSFUL_aCCESS', ACE::ACE_FLAG_SUCCESSFUL_ACCESS],
            [ACE::ACE_TYPE_SYSTEM_ALARM, 'successfulAccess', ACE::ACE_FLAG_SUCCESSFUL_ACCESS],
            [ACE::ACE_TYPE_SYSTEM_ALARM, 'suCCeSSful', ACE::ACE_FLAG_SUCCESSFUL_ACCESS],
            [ACE::ACE_TYPE_SYSTEM_AUDIT, 'FAILed_ACCESS', ACE::ACE_FLAG_FAILED_ACCESS],
            [ACE::ACE_TYPE_SYSTEM_AUDIT, 'failedAccess', ACE::ACE_FLAG_FAILED_ACCESS],
            [ACE::ACE_TYPE_SYSTEM_AUDIT, 'Failed', ACE::ACE_FLAG_FAILED_ACCESS],
            [ACE::ACE_TYPE_SYSTEM_ALARM, 'FAILed_ACCESS', ACE::ACE_FLAG_FAILED_ACCESS],
            [ACE::ACE_TYPE_SYSTEM_ALARM, 'failedAccess', ACE::ACE_FLAG_FAILED_ACCESS],
            [ACE::ACE_TYPE_SYSTEM_ALARM, 'Failed', ACE::ACE_FLAG_FAILED_ACCESS],
        ];
    }

    /**
     * @return array[]
     */
    public function aceFlagMaskInvalidTypeData()
    {
        return [
            [ACE::ACE_TYPE_ACCESS_ALLOWED, ACE::ACE_FLAG_SUCCESSFUL_ACCESS],
            [ACE::ACE_TYPE_ACCESS_ALLOWED, ACE::ACE_FLAG_FAILED_ACCESS],
            [ACE::ACE_TYPE_ACCESS_ALLOWED, ACE::ACE_FLAG_IDENTIFIER_GROUP],
            [ACE::ACE_TYPE_ACCESS_DENIED, ACE::ACE_FLAG_SUCCESSFUL_ACCESS],
            [ACE::ACE_TYPE_ACCESS_DENIED, ACE::ACE_FLAG_FAILED_ACCESS],
            [ACE::ACE_TYPE_ACCESS_DENIED, ACE::ACE_FLAG_IDENTIFIER_GROUP],
            [ACE::ACE_TYPE_SYSTEM_AUDIT, ACE::ACE_FLAG_NO_PROPAGATE_INHERIT],
            [ACE::ACE_TYPE_SYSTEM_AUDIT, ACE::ACE_FLAG_INHERIT_ONLY],
            [ACE::ACE_TYPE_SYSTEM_AUDIT, ACE::ACE_FLAG_INHERIT],
            [ACE::ACE_TYPE_SYSTEM_AUDIT, ACE::ACE_FLAG_IDENTIFIER_GROUP],
            [ACE::ACE_TYPE_SYSTEM_ALARM, ACE::ACE_FLAG_NO_PROPAGATE_INHERIT],
            [ACE::ACE_TYPE_SYSTEM_ALARM, ACE::ACE_FLAG_INHERIT_ONLY],
            [ACE::ACE_TYPE_SYSTEM_AUDIT, ACE::ACE_FLAG_INHERIT],
            [ACE::ACE_TYPE_SYSTEM_AUDIT, ACE::ACE_FLAG_IDENTIFIER_GROUP],
        ];
    }

    /**
     * @return array[]
     */
    public function aceFlagMaskMultiValueData()
    {
        return [
            [
                'type'     => ACE::ACE_TYPE_ACCESS_ALLOWED,
                'add'      => [ACE::ACE_FLAG_INHERIT, ACE::ACE_FLAG_NO_PROPAGATE_INHERIT,  ACE::ACE_FLAG_INHERIT_ONLY],
                'remove'   => [],
                'expected' => ACE::ACE_FLAG_INHERIT | ACE::ACE_FLAG_NO_PROPAGATE_INHERIT | ACE::ACE_FLAG_INHERIT_ONLY
            ],
            [
                'type'     => ACE::ACE_TYPE_ACCESS_DENIED,
                'add'      => [ACE::ACE_FLAG_INHERIT, ACE::ACE_FLAG_NO_PROPAGATE_INHERIT,  ACE::ACE_FLAG_INHERIT_ONLY],
                'remove'   => [],
                'expected' => ACE::ACE_FLAG_INHERIT | ACE::ACE_FLAG_NO_PROPAGATE_INHERIT | ACE::ACE_FLAG_INHERIT_ONLY
            ],
            [
                'type'     => ACE::ACE_TYPE_ACCESS_ALLOWED,
                'add'      => [ACE::ACE_FLAG_INHERIT, ACE::ACE_FLAG_NO_PROPAGATE_INHERIT,  ACE::ACE_FLAG_INHERIT_ONLY],
                'remove'   => [ACE::ACE_FLAG_INHERIT_ONLY],
                'expected' => ACE::ACE_FLAG_INHERIT | ACE::ACE_FLAG_NO_PROPAGATE_INHERIT
            ],
            [
                'type'     => ACE::ACE_TYPE_ACCESS_DENIED,
                'add'      => [ACE::ACE_FLAG_INHERIT, ACE::ACE_FLAG_NO_PROPAGATE_INHERIT,  ACE::ACE_FLAG_INHERIT_ONLY],
                'remove'   => [ACE::ACE_FLAG_INHERIT_ONLY],
                'expected' => ACE::ACE_FLAG_INHERIT | ACE::ACE_FLAG_NO_PROPAGATE_INHERIT
            ],
            [
                'type'     => ACE::ACE_TYPE_SYSTEM_AUDIT,
                'add'      => [ACE::ACE_FLAG_SUCCESSFUL_ACCESS, ACE::ACE_FLAG_FAILED_ACCESS],
                'remove'   => [],
                'expected' => ACE::ACE_FLAG_SUCCESSFUL_ACCESS | ACE::ACE_FLAG_FAILED_ACCESS
            ],
            [
                'type'     => ACE::ACE_TYPE_SYSTEM_AUDIT,
                'add'      => [ACE::ACE_FLAG_SUCCESSFUL_ACCESS, ACE::ACE_FLAG_FAILED_ACCESS],
                'remove'   => [ACE::ACE_FLAG_SUCCESSFUL_ACCESS],
                'expected' => ACE::ACE_FLAG_FAILED_ACCESS
            ],
            [
                'type'     => ACE::ACE_TYPE_SYSTEM_ALARM,
                'add'      => [ACE::ACE_FLAG_SUCCESSFUL_ACCESS, ACE::ACE_FLAG_FAILED_ACCESS],
                'remove'   => [],
                'expected' => ACE::ACE_FLAG_SUCCESSFUL_ACCESS | ACE::ACE_FLAG_FAILED_ACCESS
            ],
            [
                'type'     => ACE::ACE_TYPE_SYSTEM_ALARM,
                'add'      => [ACE::ACE_FLAG_SUCCESSFUL_ACCESS, ACE::ACE_FLAG_FAILED_ACCESS],
                'remove'   => [ACE::ACE_FLAG_SUCCESSFUL_ACCESS],
                'expected' => ACE::ACE_FLAG_FAILED_ACCESS
            ],
        ];
    }
}
