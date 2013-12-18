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
use CrEOF\Security\SecuredEntity\ACE\AccessMask;

/**
 * AccessMask test
 *
 * @author  Derek J. Lambert <dlambert@dereklambert.com>
 * @license http://dlambert.mit-license.org MIT
 */
class AccessMaskTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @param array $add
     * @param array $remove
     * @param int   $expected
     *
     * @test
     * @dataProvider accessMaskData
     */
    public function aceAccessMaskTest($add, $remove, $expected)
    {
        $mask = new AccessMask();

        foreach ($add as $perms) {
            $mask->add($perms);
        }

        foreach ($remove as $perms) {
            $mask->remove($perms);
        }

        $this->assertEquals($expected, $mask->get());
        $this->assertTrue($mask->equals($expected));
        $this->assertTrue($mask->contains($expected));
    }

    /**
     * @param int  $mask
     * @param int  $contains
     * @param bool $expected
     *
     * @test
     * @dataProvider accessMaskContainsData
     */
    public function aceAccessMaskContainsTest($mask, $contains, $expected)
    {
        $mask = new AccessMask($mask);

        $this->assertEquals($expected, $mask->contains($contains));
    }

    /**
     * @return array[]
     */
    public function accessMaskData()
    {
        return [
            // Add string values
            [
                'add'      => ['view', 'create'],
                'remove'   => [],
                'expected' => ACE::ACE_MASK_VIEW | ACE::ACE_MASK_CREATE
            ],
            // Add int values
            [
                'add'      => [ACE::ACE_MASK_VIEW, ACE::ACE_MASK_CREATE],
                'remove'   => [],
                'expected' => ACE::ACE_MASK_VIEW | ACE::ACE_MASK_CREATE
            ],
            // Add array of string values
            [
                'add'      => [['view', 'create']],
                'remove'   => [],
                'expected' => ACE::ACE_MASK_VIEW | ACE::ACE_MASK_CREATE
            ],
            // Add array of int values
            [
                'add'      => [[ACE::ACE_MASK_VIEW, ACE::ACE_MASK_CREATE]],
                'remove'   => [],
                'expected' => ACE::ACE_MASK_VIEW | ACE::ACE_MASK_CREATE
            ],
            // Add and remove string values
            [
                'add'      => ['view', 'create', 'modify', 'delete'],
                'remove'   => ['modify', 'delete'],
                'expected' => ACE::ACE_MASK_VIEW | ACE::ACE_MASK_CREATE
            ],
            // Add and remove array of string values
            [
                'add'      => [['view', 'create', 'modify', 'delete']],
                'remove'   => [['modify', 'delete']],
                'expected' => ACE::ACE_MASK_VIEW | ACE::ACE_MASK_CREATE
            ],
            // Add and remove int values
            [
                'add'      => [ACE::ACE_MASK_VIEW, ACE::ACE_MASK_CREATE, ACE::ACE_MASK_MODIFY, ACE::ACE_MASK_DELETE],
                'remove'   => [ACE::ACE_MASK_MODIFY, ACE::ACE_MASK_DELETE],
                'expected' => ACE::ACE_MASK_VIEW | ACE::ACE_MASK_CREATE
            ],
            // Add and remove array of int values
            [
                'add'      => [[ACE::ACE_MASK_VIEW, ACE::ACE_MASK_CREATE, ACE::ACE_MASK_MODIFY, ACE::ACE_MASK_DELETE]],
                'remove'   => [[ACE::ACE_MASK_MODIFY, ACE::ACE_MASK_DELETE]],
                'expected' => ACE::ACE_MASK_VIEW | ACE::ACE_MASK_CREATE
            ],
            // Add and remove multiple arrays of string values
            [
                'add'      => [['view', 'create'], ['modify', 'delete']],
                'remove'   => [['modify'], ['delete']],
                'expected' => ACE::ACE_MASK_VIEW | ACE::ACE_MASK_CREATE
            ],
            [
                'add'      => [ACE::ACE_MASK_VIEW, ACE::ACE_MASK_CREATE, ACE::ACE_MASK_MODIFY, ACE::ACE_MASK_DELETE, ACE::ACE_MASK_UNDELETE, ACE::ACE_MASK_SEARCH, ACE::ACE_MASK_READ_ATTRIBUTES, ACE::ACE_MASK_WRITE_ATTRIBUTES, ACE::ACE_MASK_READ_ACL, ACE::ACE_MASK_WRITE_ACL, ACE::ACE_MASK_WRITE_OWNER],
                'remove'   => [],
                'expected' => ACE::ACE_MASK_FULL_CONTROL
            ],
            [
                'add'      => ['view', 'create', 'modify', 'delete', 'undelete', 'search', 'read_attributes', 'write_attributes', 'read_acl', 'write_acl', 'write_owner'],
                'remove'   => [],
                'expected' => ACE::ACE_MASK_FULL_CONTROL
            ],
            [
                'add'      => ['readAttributes', 'writeAttributes', 'readAcl', 'writeAcl', 'writeOwner'],
                'remove'   => [],
                'expected' => ACE::ACE_MASK_READ_ATTRIBUTES | ACE::ACE_MASK_WRITE_ATTRIBUTES | ACE::ACE_MASK_READ_ACL | ACE::ACE_MASK_WRITE_ACL | ACE::ACE_MASK_WRITE_OWNER
            ]
        ];
    }

    /**
     * @return array[]
     */
    public function accessMaskContainsData()
    {
        return [
            [
                'mask'     => ACE::ACE_MASK_VIEW | ACE::ACE_MASK_CREATE | ACE::ACE_MASK_MODIFY | ACE::ACE_MASK_DELETE,
                'contains' => ACE::ACE_MASK_VIEW | ACE::ACE_MASK_MODIFY,
                'expected' => true
            ],
            [
                'mask'     => ACE::ACE_MASK_VIEW | ACE::ACE_MASK_CREATE | ACE::ACE_MASK_MODIFY | ACE::ACE_MASK_DELETE,
                'contains' => ACE::ACE_MASK_VIEW | ACE::ACE_MASK_MODIFY | ACE::ACE_MASK_DELETE,
                'expected' => true
            ],
            [
                'mask'     => ACE::ACE_MASK_VIEW | ACE::ACE_MASK_CREATE | ACE::ACE_MASK_MODIFY | ACE::ACE_MASK_DELETE,
                'contains' => ACE::ACE_MASK_VIEW | ACE::ACE_MASK_MODIFY | ACE::ACE_MASK_DELETE,
                'expected' => true
            ],
            [
                'mask'     => ACE::ACE_MASK_FULL_CONTROL,
                'contains' => ACE::ACE_MASK_SEARCH | ACE::ACE_MASK_UNDELETE | ACE::ACE_MASK_WRITE_OWNER,
                'expected' => true
            ],
            [
                'mask'     => ACE::ACE_MASK_FULL_CONTROL,
                'contains' => ACE::ACE_MASK_VIEW | ACE::ACE_MASK_CREATE | ACE::ACE_MASK_MODIFY | ACE::ACE_MASK_DELETE | ACE::ACE_MASK_UNDELETE | ACE::ACE_MASK_SEARCH | ACE::ACE_MASK_READ_ATTRIBUTES | ACE::ACE_MASK_WRITE_ATTRIBUTES | ACE::ACE_MASK_READ_ACL | ACE::ACE_MASK_WRITE_ACL | ACE::ACE_MASK_WRITE_OWNER,
                'expected' => true
            ],
            [
                'mask'     => ACE::ACE_MASK_VIEW | ACE::ACE_MASK_CREATE | ACE::ACE_MASK_MODIFY | ACE::ACE_MASK_DELETE | ACE::ACE_MASK_UNDELETE | ACE::ACE_MASK_SEARCH | ACE::ACE_MASK_READ_ATTRIBUTES | ACE::ACE_MASK_WRITE_ATTRIBUTES | ACE::ACE_MASK_READ_ACL | ACE::ACE_MASK_WRITE_ACL | ACE::ACE_MASK_WRITE_OWNER,
                'contains' => ACE::ACE_MASK_FULL_CONTROL,
                'expected' => true
            ],
            [
                'mask'     => ACE::ACE_MASK_VIEW | ACE::ACE_MASK_CREATE,
                'contains' => ACE::ACE_MASK_DELETE,
                'expected' => false
            ],
            [
                'mask'     => ACE::ACE_MASK_VIEW | ACE::ACE_MASK_CREATE,
                'contains' => ACE::ACE_MASK_VIEW | ACE::ACE_MASK_DELETE,
                'expected' => false
            ],
            [
                'mask'     => ACE::ACE_MASK_VIEW | ACE::ACE_MASK_CREATE | ACE::ACE_MASK_MODIFY | ACE::ACE_MASK_DELETE | ACE::ACE_MASK_UNDELETE | ACE::ACE_MASK_SEARCH | ACE::ACE_MASK_READ_ATTRIBUTES | ACE::ACE_MASK_WRITE_ATTRIBUTES | ACE::ACE_MASK_READ_ACL | ACE::ACE_MASK_WRITE_ACL,
                'contains' => ACE::ACE_MASK_FULL_CONTROL,
                'expected' => false
            ]
        ];
    }
}
