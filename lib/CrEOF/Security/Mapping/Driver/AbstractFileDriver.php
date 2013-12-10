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

use CrEOF\Security\Mapping\DriverInterface;
use Doctrine\Common\Persistence\Mapping\Driver\FileDriver;
use Doctrine\Common\Persistence\Mapping\Driver\FileLocator;
use Doctrine\Common\Persistence\Mapping\Driver\MappingDriver;

/**
 * AbstractFileDriver defines common metadata extraction functions for file-based drivers
 *
 * @author  Derek J. Lambert <dlambert@dereklambert.com>
 * @license http://dlambert.mit-license.org MIT
 */
abstract class AbstractFileDriver implements DriverInterface
{
    /**
     * @var FileLocator
     */
    protected $locator;

    /**
     * File extension, must be set in child class
     *
     * @var string
     */
    protected $extension;

    /**
     * @var array
     */
    protected $paths = [];

    /**
     * @var MappingDriver
     */
    protected $originalDriver = null;

    /**
     * Passes in the mapping read by original driver
     *
     * @param MappingDriver $driver
     *
     * @return AbstractFileDriver
     */
    public function setOriginalDriver(MappingDriver $driver)
    {
        $this->originalDriver = $driver;

        return $this;
    }

    /**
     * @param FileLocator $locator
     *
     * @return AbstractFileDriver
     */
    public function setLocator(FileLocator $locator)
    {
        $this->locator = $locator;

        return $this;
    }

    /**
     * Set the paths for file lookup
     *
     * @param array $paths
     *
     * @return AbstractFileDriver
     */
    public function setPaths($paths)
    {
        $this->paths = (array) $paths;

        return $this;
    }

    /**
     * Set the file extension
     *
     * @param string $extension
     *
     * @return AbstractFileDriver
     */
    public function setExtension($extension)
    {
        $this->extension = $extension;

        return $this;
    }

    /**
     * Tries to get a mapping for a given class
     *
     * @param string $className
     *
     * @return null|array|object
     */
    protected function getMapping($className)
    {
        //try loading mapping from original driver first
        $mapping = null;

        if (null !== $this->originalDriver && ($this->originalDriver instanceof FileDriver || $this->originalDriver instanceof AbstractFileDriver)) {
            $mapping = $this->originalDriver->getElement($className);
        }

        //if no mapping found try to load mapping file again
        if (null === $mapping) {
            //$yaml = $this->loadMappingFile($this->locator->findMappingFile($className));
            //$mapping = $yaml[$className];
            $mapping = $this->loadMappingFile($this->locator->findMappingFile($className))[$className];
        }

        return $mapping;
    }

    /**
     * Loads a mapping file and returns a map of class/entity names to corresponding elements
     *
     * @param string $file
     *
     * @return array
     */
    abstract protected function loadMappingFile($file);
}
