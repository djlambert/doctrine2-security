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

use CrEOF\Security\SecuredEntity\SID;

/**
 * test
 *
 * @author  Derek J. Lambert <dlambert@dereklambert.com>
 * @license http://dlambert.mit-license.org MIT
 */
class SIDTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function sidGroupTest()
    {
        $sid = new SID();

        $sid->set('security_group', true);

        $this->assertEquals(true, $sid->isGroup());
    }

    /**
     * @test
     */
    public function sidGroupFlipTest()
    {
        $sid = new SID();

        $sid->set('security_group', true);
        $sid->set('user');

        $this->assertEquals(false, $sid->isGroup());
    }

    /**
     * @test
     */
    public function sidGroupFlipFlipTest()
    {
        $sid = new SID();

        $sid->set('security_group', true);
        $sid->set('security_group2', true);

        $this->assertEquals(true, $sid->isGroup());
    }

    /**
     * @param string $passedSid
     * @param string $expectedSid
     * @param bool   $isSpecial
     *
     * @test
     * @dataProvider specialSidData
     */
    public function sidSpecialTest($passedSid, $expectedSid, $isSpecial)
    {
        $sid = new SID();

        $sid->set($passedSid);

        $this->assertEquals($expectedSid, $sid->get());
        $this->assertEquals($isSpecial, $sid->isSpecial());
    }

    /**
     * @return array[]
     */
    public function specialSidData()
    {
        return [
          ['Owner', 'OWNER@', true],
          ['GROUP@', 'GROUP@', true],
          ['everyone', 'EVERYONE@', true],
          ['interactive', 'INTERACTIVE@', true],
          ['network', 'NETWORK@', true],
          ['dialUp', 'DIALUP@', true],
          ['batch', 'BATCH@', true],
          ['anonymous', 'ANONYMOUS@', true],
          ['authenticated', 'AUTHENTICATED@', true],
          ['service', 'SERVICE@', true],
          ['username', 'username', false],
          ['JohnDoe', 'JohnDoe', false]
        ];
    }

}
