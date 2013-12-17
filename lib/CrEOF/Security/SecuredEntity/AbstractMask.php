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
 * AbstractMask class
 *
 * @author  Derek J. Lambert <dlambert@dereklambert.com>
 * @license http://dlambert.mit-license.org MIT
 */
abstract class AbstractMask extends AbstractSimpleMask
{
    /**
     * Adds a mask to the mask
     *
     * @param mixed $mask
     *
     * @return AbstractMask
     */
    public function add($mask)
    {
        $this->mask |= $this->getMask($mask);

        return $this;
    }

    /**
     * Removes a mask from the mask
     *
     * @param mixed $mask
     *
     * @return AbstractMask
     */
    public function remove($mask)
    {
        $this->mask &= ~$this->getMask($mask);

        return $this;
    }

    /**
     * @param int $mask
     *
     * @return bool
     */
    public function contains($mask)
    {
        $mask = $this->getMask($mask);

        return $mask === ($this->mask & $mask);
    }

    /**
     * Reset mask to all zeros
     *
     * @return AbstractMask
     */
    public function reset()
    {
        $this->mask = 0;

        return $this;
    }

    /**
     * @param mixed $mask
     *
     * @return int
     * @throws InvalidArgumentException
     */
    protected function getMask($mask)
    {
        if (is_array($mask)) {
            $mask = array_reduce($mask, function ($combined, $val) {
                return $combined |= $this->getMask($val);
            }, 0);
        }

        return parent::getMask($mask);
    }
}
