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

use CrEOF\Security\Exception\InvalidMappingException;
use SimpleXMLElement;


/**
 * AbstractXmlDriver defines common metadata extraction functions for XML file-based drivers
 *
 * @author  Derek J. Lambert <dlambert@dereklambert.com>
 * @license http://dlambert.mit-license.org MIT
 */
abstract class AbstractXmlDriver extends AbstractFileDriver
{
    const PROJECT_NAMESPACE_URI = 'http://creof.com/schemas/orm/doctrine2-security-mapping';
    const DOCTRINE_NAMESPACE_URI = 'http://doctrine-project.org/schemas/orm/doctrine-mapping';

    /**
     * File extension
     *
     * @var string
     */
    protected $extension = '.dcm.xml';

    /**
     * Get attribute value
     *
     * As we are supporting namespaces the only way to get to the attributes under a node is to use attributes function on it
     *
     * @param SimpleXMLElement $node
     * @param string           $attributeName
     *
     * @return string
     */
    protected function getAttribute(SimpleXmlElement $node, $attributeName)
    {
        $attributes = $node->attributes();

        return (string) $attributes[$attributeName];
    }

    /**
     * Get boolean attribute value
     *
     * As we are supporting namespaces the only way to get to the attributes under a node is to use attributes function on it
     *
     * @param SimpleXMLElement $node
     * @param string           $attributeName
     *
     * @throws InvalidMappingException
     *
     * @return bool
     */
    protected function getBooleanAttribute(SimpleXmlElement $node, $attributeName)
    {
        $value = strtolower($rawValue = $this->getAttribute($node, $attributeName));

        if ($value === '1' || $value === 'true') {
            return true;
        }

        if ($value === '0' || $value === 'false') {
            return false;
        }

        throw InvalidMappingException::attributeValueNotBoolean($attributeName, $rawValue);
    }

    /**
     * does attribute exist under a specific node
     *
     * As we are supporting namespaces the only way to get to the attributes under a node is to use attributes function on it
     *
     * @param SimpleXMLElement $node
     * @param string           $attributeName
     *
     * @return string
     */
    protected function isAttributeSet(SimpleXmlElement $node, $attributeName)
    {
        $attributes = $node->attributes();

        return isset($attributes[$attributeName]);
    }

    /**
     * {@inheritDoc}
     */
    protected function loadMappingFile($file)
    {
        $result     = [];
        $xmlElement = simplexml_load_file($file);
        $xmlElement = $xmlElement->children(self::DOCTRINE_NAMESPACE_URI);

        if (isset($xmlElement->entity)) {
            foreach ($xmlElement->entity as $entityElement) {
                $result[$this->getAttribute($entityElement, 'name')] = $entityElement;
            }
        } elseif (isset($xmlElement->{'mapped-superclass'})) {
            foreach ($xmlElement->{'mapped-superclass'} as $mappedSuperClass) {
                $result[$this->getAttribute($mappedSuperClass, 'name')] = $mappedSuperClass;
            }
        }

        return $result;
    }
}
