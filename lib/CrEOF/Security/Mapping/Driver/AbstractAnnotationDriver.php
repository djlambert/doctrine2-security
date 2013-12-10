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

namespace CrEOF\Security\Mapping\Driver;

use Doctrine\Common\Annotations\Reader;
use Doctrine\Common\Persistence\Mapping\Driver\MappingDriver;

/**
 * AbstractAnnotationDriver
 *
 * Annotation mapping driver common code
 *
 * @author  Derek J. Lambert <dlambert@dereklambert.com>
 * @license http://dlambert.mit-license.org MIT
 */
abstract class AbstractAnnotationDriver implements AnnotationDriverInterface
{
    /**
     * Annotation reader
     *
     * @var Reader
     */
    protected $reader;

    /**
     * Original driver if it is available
     *
     * @var MappingDriver
     */
    protected $originalDriver = null;

    /**
     * Set annotation reader class
     *
     * @param Reader $reader
     *
     * @return AbstractAnnotationDriver
     */
    public function setAnnotationReader(Reader $reader)
    {
        $this->reader = $reader;

        return $this;
    }

    /**
     * Passes in the mapping read by original driver
     *
     * @param MappingDriver $driver
     *
     * @return AbstractAnnotationDriver
     */
    public function setOriginalDriver(MappingDriver $driver)
    {
        $this->originalDriver = $driver;

        return $this;
    }
}
