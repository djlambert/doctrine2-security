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
use CrEOF\Security\SecuredEntity\ACE\TypeMask;

/**
 * TypeMask test
 *
 * @author  Derek J. Lambert <dlambert@dereklambert.com>
 * @license http://dlambert.mit-license.org MIT
 */
class TypeMaskTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @param mixed $type
     * @param int   $expected
     *
     * @test
     * @dataProvider aceTypeMaskData
     */
    public function aceTypeMaskTest($type, $expected)
    {
        $mask = new TypeMask($type);

        $this->assertEquals($expected, $mask->get());
    }

    /**
     * @param mixed $type
     *
     * @test
     * @dataProvider      aceBadTypeMaskData
     * @expectedException InvalidArgumentException
     */
    public function aceBadTypeMaskTest($type)
    {
        new TypeMask($type);
    }

    /**
     * @return array[]
     */
    public function aceTypeMaskData()
    {
        return [
            [ACE::ACE_TYPE_ACCESS_ALLOWED, ACE::ACE_TYPE_ACCESS_ALLOWED],
            [ACE::ACE_TYPE_ACCESS_DENIED, ACE::ACE_TYPE_ACCESS_DENIED],
            [ACE::ACE_TYPE_SYSTEM_AUDIT, ACE::ACE_TYPE_SYSTEM_AUDIT],
            [ACE::ACE_TYPE_SYSTEM_ALARM, ACE::ACE_TYPE_SYSTEM_ALARM],
            ['allow', ACE::ACE_TYPE_ACCESS_ALLOWED],
            ['Access_Allowed', ACE::ACE_TYPE_ACCESS_ALLOWED],
            ['accessAllowed', ACE::ACE_TYPE_ACCESS_ALLOWED],
            ['Deny', ACE::ACE_TYPE_ACCESS_DENIED],
            ['access_denied', ACE::ACE_TYPE_ACCESS_DENIED],
            ['accessDenied', ACE::ACE_TYPE_ACCESS_DENIED],
            ['auDiT', ACE::ACE_TYPE_SYSTEM_AUDIT],
            ['SYSTEM_AUDIT', ACE::ACE_TYPE_SYSTEM_AUDIT],
            ['systemAudit', ACE::ACE_TYPE_SYSTEM_AUDIT],
            ['ALARM', ACE::ACE_TYPE_SYSTEM_ALARM],
            ['sYsTem_AlarM', ACE::ACE_TYPE_SYSTEM_ALARM],
            ['systemAlarm', ACE::ACE_TYPE_SYSTEM_ALARM]
        ];
    }

    /**
     * @return array[]
     */
    public function aceBadTypeMaskData()
    {
        return [
            ['allows'],
            [27],
            [2.2],
            ['1'],
            ['access-denied']
        ];
    }
}
