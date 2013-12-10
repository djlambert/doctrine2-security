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
use Doctrine\Common\Persistence\Mapping\Driver\MappingDriver;
use Doctrine\ORM\Mapping\ClassMetadata;

/**
 * The chain mapping driver enables chained extension mapping driver support
 *
 * @author  Derek J. Lambert <dlambert@dereklambert.com>
 * @license http://dlambert.mit-license.org MIT
 */
class ChainDriver implements DriverInterface
{
    /**
     * The default driver
     *
     * @var DriverInterface|null
     */
    private $defaultDriver;

    /**
     * List of drivers nested
     *
     * @var DriverInterface[]
     */
    private $drivers = [];

    /**
     * {@inheritDoc}
     */
    public function readExtendedMetadata(ClassMetadata $metadata, array &$config)
    {
        foreach ($this->drivers as $namespace => $driver) {
            if (strpos($metadata->name, $namespace) === 0) {
                $driver->readExtendedMetadata($metadata, $config);

                return;
            }
        }

        if (null !== $this->defaultDriver) {
            $this->defaultDriver->readExtendedMetadata($metadata, $config);

            return;
        }

        // commenting it for customized mapping support, debugging of such cases might get harder
        //throw new \Gedmo\Exception\UnexpectedValueException('Class ' . $meta->name . ' is not a valid entity or mapped super class.');
    }

    /**
     * {@inheritDoc}
     */
    public function setOriginalDriver(MappingDriver $driver)
    {
        return $this;
    }

    /**
     * Get the array of nested drivers
     *
     * @return DriverInterface[]
     */
    public function getDrivers()
    {
        return $this->drivers;
    }

    /**
     * Get the default driver
     *
     * @return DriverInterface|null
     */
    public function getDefaultDriver()
    {
        return $this->defaultDriver;
    }

    /**
     * Set the default driver
     *
     * @param DriverInterface $driver
     *
     * @return ChainDriver
     */
    public function setDefaultDriver(DriverInterface $driver)
    {
        $this->defaultDriver = $driver;

        return $this;
    }

    /**
     * Add a nested driver
     *
     * @param DriverInterface $nestedDriver
     * @param string          $namespace
     *
     * @return ChainDriver
     */
    public function addDriver(DriverInterface $nestedDriver, $namespace)
    {
        $this->drivers[$namespace] = $nestedDriver;

        return $this;
    }
}
