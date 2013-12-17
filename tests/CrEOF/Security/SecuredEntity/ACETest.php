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

use CrEOF\Security\SecuredEntity\ACE;
use CrEOF\Security\SecuredEntity\SID;

/**
 * test
 *
 * @author  Derek J. Lambert <dlambert@dereklambert.com>
 * @license http://dlambert.mit-license.org MIT
 */
class ACETest extends \PHPUnit_Framework_TestCase
{
    /**
     * @param int $typeMask
     *
     * @test
     * @dataProvider aceTypeMaskData
     */
    public function aceTypeTest($typeMask)
    {
        $ace = new ACE($typeMask);

        $this->assertEquals($typeMask, $ace->type->get());
    }

    /**
     * @test
     */
    public function aceTypeDefaultTest()
    {
        $ace = new ACE();

        $this->assertEquals(ACE::ACE_TYPE_ACCESS_ALLOWED, $ace->type->get());
    }

    /**
     * @test
     * @expectedException        \CrEOF\Security\Exception\InvalidArgumentException
     * @expectedExceptionMessage ACE type mask "0x00000012" is not supported
     */
    public function aceBadTypeTest()
    {
        $ace = new ACE(10);
    }

    /**
     * @test
     */
    public function aceGroupSidTest()
    {
        $ace = new ACE();

        $ace->setSid('security_group', true);

        $this->assertEquals(true, $ace->getSid()->isGroup());
        $this->assertEquals(false, $ace->getSid()->isSpecial());
    }

    /**
     * @test
     */
    public function aceRegularSidTest()
    {
        $ace = new ACE();

        $ace->setSid('JoeUser');

        $this->assertEquals(false, $ace->getSid()->isGroup());
        $this->assertEquals(false, $ace->getSid()->isSpecial());
    }

    /**
     * @test
     */
    public function aceSpecialSidTest()
    {
        $ace = new ACE();

        $ace->setSid('group');

        $this->assertEquals(false, $ace->getSid()->isGroup());
        $this->assertEquals(true, $ace->getSid()->isSpecial());
        $this->assertEquals('GROUP@', $ace->getSid()->get());
    }

    /**
     * @param array $add
     * @param array $remove
     * @param int   $expected
     *
     * @test
     * @dataProvider aceAccessMaskData
     */
    public function acePermissionTest($add, $remove, $expected)
    {
        $ace = new ACE();

        foreach ($add as $perms) {
            $ace->access->add($perms);
        }

        foreach ($remove as $perms) {
            $ace->access->remove($perms);
        }

        $this->assertEquals($expected, $ace->access->get());
    }

    /**
     * @param int   $type
     * @param array $add
     * @param array $remove
     * @param int   $expected
     *
     * @test
     * @dataProvider aceFlagMaskData
     */
    public function aceFlagTest($type, $add, $remove, $expected)
    {
        $ace = new ACE($type);

        foreach ($add as $flags) {
            $ace->flag->add($flags);
        }

        foreach ($remove as $flags) {
            $ace->flag->remove($flags);
        }

        $this->assertEquals($expected, $ace->flag->get());
    }

    /**
     * @return array[]
     */
    public function aceTypeMaskData()
    {
        return [
            [ACE::ACE_TYPE_ACCESS_ALLOWED],
            [ACE::ACE_TYPE_ACCESS_DENIED],
            [ACE::ACE_TYPE_SYSTEM_AUDIT],
            [ACE::ACE_TYPE_SYSTEM_ALARM]
        ];
    }

    /**
     * @return array[]
     */
    public function aceAccessMaskData()
    {
        return [
            // Add string values
            [
                'add'      => ['view', 'create'],
                'remove'   => [],
                'expected' => ACE::ACE_MASK_VIEW + ACE::ACE_MASK_CREATE
            ],
            // Add int values
            [
                'add'      => [ACE::ACE_MASK_VIEW, ACE::ACE_MASK_CREATE],
                'remove'   => [],
                'expected' => ACE::ACE_MASK_VIEW + ACE::ACE_MASK_CREATE
            ],
            // Add array of string values
            [
                'add'      => [['view', 'create']],
                'remove'   => [],
                'expected' => ACE::ACE_MASK_VIEW + ACE::ACE_MASK_CREATE
            ],
            // Add array of int values
            [
                'add'      => [[ACE::ACE_MASK_VIEW, ACE::ACE_MASK_CREATE]],
                'remove'   => [],
                'expected' => ACE::ACE_MASK_VIEW + ACE::ACE_MASK_CREATE
            ],
            // Add and remove string values
            [
                'add'      => ['view', 'create', 'modify', 'delete'],
                'remove'   => ['modify', 'delete'],
                'expected' => ACE::ACE_MASK_VIEW + ACE::ACE_MASK_CREATE
            ],
            // Add and remove array of string values
            [
                'add'      => [['view', 'create', 'modify', 'delete']],
                'remove'   => [['modify', 'delete']],
                'expected' => ACE::ACE_MASK_VIEW + ACE::ACE_MASK_CREATE
            ],
            // Add and remove int values
            [
                'add'      => [ACE::ACE_MASK_VIEW, ACE::ACE_MASK_CREATE, ACE::ACE_MASK_MODIFY, ACE::ACE_MASK_DELETE],
                'remove'   => [ACE::ACE_MASK_MODIFY, ACE::ACE_MASK_DELETE],
                'expected' => ACE::ACE_MASK_VIEW + ACE::ACE_MASK_CREATE
            ],
            // Add and remove array of int values
            [
                'add'      => [[ACE::ACE_MASK_VIEW, ACE::ACE_MASK_CREATE, ACE::ACE_MASK_MODIFY, ACE::ACE_MASK_DELETE]],
                'remove'   => [[ACE::ACE_MASK_MODIFY, ACE::ACE_MASK_DELETE]],
                'expected' => ACE::ACE_MASK_VIEW + ACE::ACE_MASK_CREATE
            ],
            // Add and remove multiple arrays of string values
            [
                'add'      => [['view', 'create'], ['modify', 'delete']],
                'remove'   => [['modify'], ['delete']],
                'expected' => ACE::ACE_MASK_VIEW + ACE::ACE_MASK_CREATE
            ],
        ];
    }

    /**
     * @return array[]
     */
    public function aceFlagMaskData()
    {
        return [
            [
                'type'     => ACE::ACE_TYPE_ACCESS_ALLOWED,
                'add'      => ['inherit'],
                'remove'   => [],
                'expected' => ACE::ACE_FLAG_INHERIT
            ],
            [
                'type'     => ACE::ACE_TYPE_ACCESS_ALLOWED,
                'add'      => [ACE::ACE_FLAG_INHERIT],
                'remove'   => [],
                'expected' => ACE::ACE_FLAG_INHERIT
            ],
            [
                'type'     => ACE::ACE_TYPE_ACCESS_DENIED,
                'add'      => ['inherit'],
                'remove'   => [],
                'expected' => ACE::ACE_FLAG_INHERIT
            ],
            [
                'type'     => ACE::ACE_TYPE_ACCESS_DENIED,
                'add'      => [ACE::ACE_FLAG_INHERIT],
                'remove'   => [],
                'expected' => ACE::ACE_FLAG_INHERIT
            ],
            [
                'type'     => ACE::ACE_TYPE_ACCESS_ALLOWED,
                'add'      => ['inherit', 'no_propagate_inherit', 'inherit_only'],
                'remove'   => [],
                'expected' => ACE::ACE_FLAG_INHERIT + ACE::ACE_FLAG_NO_PROPAGATE_INHERIT + ACE::ACE_FLAG_INHERIT_ONLY
            ],
            [
                'type'     => ACE::ACE_TYPE_ACCESS_ALLOWED,
                'add'      => [ACE::ACE_FLAG_INHERIT, ACE::ACE_FLAG_NO_PROPAGATE_INHERIT,  ACE::ACE_FLAG_INHERIT_ONLY],
                'remove'   => [],
                'expected' => ACE::ACE_FLAG_INHERIT + ACE::ACE_FLAG_NO_PROPAGATE_INHERIT + ACE::ACE_FLAG_INHERIT_ONLY
            ],
            [
                'type'     => ACE::ACE_TYPE_ACCESS_DENIED,
                'add'      => ['inherit', 'no_propagate_inherit', 'inherit_only'],
                'remove'   => [],
                'expected' => ACE::ACE_FLAG_INHERIT + ACE::ACE_FLAG_NO_PROPAGATE_INHERIT + ACE::ACE_FLAG_INHERIT_ONLY
            ],
            [
                'type'     => ACE::ACE_TYPE_ACCESS_DENIED,
                'add'      => [ACE::ACE_FLAG_INHERIT, ACE::ACE_FLAG_NO_PROPAGATE_INHERIT,  ACE::ACE_FLAG_INHERIT_ONLY],
                'remove'   => [],
                'expected' => ACE::ACE_FLAG_INHERIT + ACE::ACE_FLAG_NO_PROPAGATE_INHERIT + ACE::ACE_FLAG_INHERIT_ONLY
            ],
            [
                'type'     => ACE::ACE_TYPE_SYSTEM_AUDIT,
                'add'      => [ACE::ACE_FLAG_SUCCESSFUL_ACCESS],
                'remove'   => [],
                'expected' => ACE::ACE_FLAG_SUCCESSFUL_ACCESS
            ],
            [
                'type'     => ACE::ACE_TYPE_SYSTEM_AUDIT,
                'add'      => ['successful'],
                'remove'   => [],
                'expected' => ACE::ACE_FLAG_SUCCESSFUL_ACCESS
            ],
            [
                'type'     => ACE::ACE_TYPE_SYSTEM_AUDIT,
                'add'      => [ACE::ACE_FLAG_FAILED_ACCESS],
                'remove'   => [],
                'expected' => ACE::ACE_FLAG_FAILED_ACCESS
            ],
            [
                'type'     => ACE::ACE_TYPE_SYSTEM_AUDIT,
                'add'      => ['failed'],
                'remove'   => [],
                'expected' => ACE::ACE_FLAG_FAILED_ACCESS
            ],
            [
                'type'     => ACE::ACE_TYPE_SYSTEM_AUDIT,
                'add'      => [ACE::ACE_FLAG_SUCCESSFUL_ACCESS, ACE::ACE_FLAG_FAILED_ACCESS],
                'remove'   => [],
                'expected' => ACE::ACE_FLAG_SUCCESSFUL_ACCESS + ACE::ACE_FLAG_FAILED_ACCESS
            ],
            [
                'type'     => ACE::ACE_TYPE_SYSTEM_AUDIT,
                'add'      => ['successful', 'failed'],
                'remove'   => [],
                'expected' => ACE::ACE_FLAG_SUCCESSFUL_ACCESS + ACE::ACE_FLAG_FAILED_ACCESS
            ],
            [
                'type'     => ACE::ACE_TYPE_SYSTEM_AUDIT,
                'add'      => [ACE::ACE_FLAG_SUCCESSFUL_ACCESS, ACE::ACE_FLAG_FAILED_ACCESS],
                'remove'   => [ACE::ACE_FLAG_SUCCESSFUL_ACCESS],
                'expected' => ACE::ACE_FLAG_FAILED_ACCESS
            ],
            [
                'type'     => ACE::ACE_TYPE_SYSTEM_AUDIT,
                'add'      => ['successful', 'failed'],
                'remove'   => ['failed'],
                'expected' => ACE::ACE_FLAG_SUCCESSFUL_ACCESS
            ],
            [
                'type'     => ACE::ACE_TYPE_SYSTEM_ALARM,
                'add'      => [ACE::ACE_FLAG_SUCCESSFUL_ACCESS],
                'remove'   => [],
                'expected' => ACE::ACE_FLAG_SUCCESSFUL_ACCESS
            ],
            [
                'type'     => ACE::ACE_TYPE_SYSTEM_ALARM,
                'add'      => ['successful'],
                'remove'   => [],
                'expected' => ACE::ACE_FLAG_SUCCESSFUL_ACCESS
            ],
            [
                'type'     => ACE::ACE_TYPE_SYSTEM_ALARM,
                'add'      => [ACE::ACE_FLAG_FAILED_ACCESS],
                'remove'   => [],
                'expected' => ACE::ACE_FLAG_FAILED_ACCESS
            ],
            [
                'type'     => ACE::ACE_TYPE_SYSTEM_ALARM,
                'add'      => ['failed'],
                'remove'   => [],
                'expected' => ACE::ACE_FLAG_FAILED_ACCESS
            ],
            [
                'type'     => ACE::ACE_TYPE_SYSTEM_ALARM,
                'add'      => [ACE::ACE_FLAG_SUCCESSFUL_ACCESS, ACE::ACE_FLAG_FAILED_ACCESS],
                'remove'   => [],
                'expected' => ACE::ACE_FLAG_SUCCESSFUL_ACCESS + ACE::ACE_FLAG_FAILED_ACCESS
            ],
            [
                'type'     => ACE::ACE_TYPE_SYSTEM_ALARM,
                'add'      => ['successful', 'failed'],
                'remove'   => [],
                'expected' => ACE::ACE_FLAG_SUCCESSFUL_ACCESS + ACE::ACE_FLAG_FAILED_ACCESS
            ],
            [
                'type'     => ACE::ACE_TYPE_SYSTEM_ALARM,
                'add'      => [ACE::ACE_FLAG_SUCCESSFUL_ACCESS, ACE::ACE_FLAG_FAILED_ACCESS],
                'remove'   => [ACE::ACE_FLAG_SUCCESSFUL_ACCESS],
                'expected' => ACE::ACE_FLAG_FAILED_ACCESS
            ],
            [
                'type'     => ACE::ACE_TYPE_SYSTEM_ALARM,
                'add'      => ['successful', 'failed'],
                'remove'   => ['failed'],
                'expected' => ACE::ACE_FLAG_SUCCESSFUL_ACCESS
            ],
        ];
    }
}
