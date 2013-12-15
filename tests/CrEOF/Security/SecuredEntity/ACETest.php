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

/**
 * test
 *
 * @author  Derek J. Lambert <dlambert@dereklambert.com>
 * @license http://dlambert.mit-license.org MIT
 */
class ACETest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function aceTypeDeniedTest()
    {
        $ace = new ACE(ACE::ACE_TYPE_ACCESS_DENIED);

        $this->assertEquals(ACE::ACE_TYPE_ACCESS_DENIED, $ace->getType());
    }

    /**
     * @test
     */
    public function aceTypeAuditTest()
    {
        $ace = new ACE(ACE::ACE_TYPE_SYSTEM_AUDIT);

        $this->assertEquals(ACE::ACE_TYPE_SYSTEM_AUDIT, $ace->getType());
    }

    /**
     * @test
     */
    public function aceTypeAllowTest()
    {
        $ace = new ACE(ACE::ACE_TYPE_ACCESS_ALLOWED);

        $this->assertEquals(ACE::ACE_TYPE_ACCESS_ALLOWED, $ace->getType());
    }

    /**
     * @test
     */
    public function aceTypeAlarmTest()
    {
        $ace = new ACE(ACE::ACE_TYPE_SYSTEM_ALARM);

        $this->assertEquals(ACE::ACE_TYPE_SYSTEM_ALARM, $ace->getType());
    }

    /**
     * @test
     */
    public function aceTypeDefaultTest()
    {
        $ace = new ACE();

        $this->assertEquals(ACE::ACE_TYPE_ACCESS_ALLOWED, $ace->getType());
    }

    /**
     * @test
     */
    public function aceGroupSidTest()
    {
        $ace = new ACE();

        $ace->setSid('security_group', true);

        $this->assertEquals(true, $ace->isGroupSid());
    }

    /**
     * @test
     */
    public function aceGroupSidFlipTest()
    {
        $ace = new ACE();

        $ace->setSid('security_group', true);
        $ace->setSid('user');

        $this->assertEquals(false, $ace->isGroupSid());
    }

    /**
     * @test
     */
    public function aceGroupSidFlipFlipTest()
    {
        $ace = new ACE();

        $ace->setSid('security_group', true);
        $ace->setSid('security_group2', true);

        $this->assertEquals(true, $ace->isGroupSid());
    }

    /**
     * @param string $sid
     * @param bool   $isSpecialSid
     *
     * @test
     * @dataProvider specialSidData
     */
    public function aceSpecialSidTest($sid, $isSpecialSid)
    {
        $ace = new ACE();

        $ace->setSid($sid);

        $this->assertEquals($isSpecialSid, $ace->isSpecialSid());
    }

    /**
     * @return string[]
     */
    public function specialSidData()
    {
        return [
          ['Owner', true],
          ['GROUP@', true],
          ['everyone', true],
          ['interactive', true],
          ['network', true],
          ['dialup', true],
          ['batch', true],
          ['anonymous', true],
          ['authenticated', true],
          ['service', true],
          ['username', false]
        ];
    }

}
