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

namespace CrEOF\Security\Tool\Logging\DBAL;

use Doctrine\DBAL\Logging\SQLLogger;
use Doctrine\DBAL\Types\Type;
use Doctrine\DBAL\Platforms\AbstractPlatform;

/**
 *
 * @author  Derek J. Lambert <dlambert@dereklambert.com>
 * @license http://dlambert.mit-license.org MIT
 */
class QueryAnalyzer implements SQLLogger
{
    /**
     * Used database platform
     *
     * @var AbstractPlatform
     */
    protected $platform;

    /**
     * Start time of currently executed query
     *
     * @var integer
     */
    private $queryStartTime = null;

    /**
     * Total execution time of all queries
     *
     * @var integer
     */
    private $totalExecutionTime = 0;

    /**
     * List of queries executed
     *
     * @var array
     */
    private $queries = [];

    /**
     * Query execution times indexed in same order as queries
     *
     * @var array
     */
    private $queryExecutionTimes = [];

    /**
     * Initialize log listener with database platform, which is needed for parameter conversion
     *
     * @param AbstractPlatform $platform
     */
    public function __construct(AbstractPlatform $platform)
    {
        $this->platform = $platform;
    }

    /**
     * {@inheritdoc}
     */
    public function startQuery($sql, array $params = null, array $types = null)
    {
        $this->queryStartTime = microtime(true);
        $this->queries[]      = $this->generateSql($sql, $params, $types);
    }

    /**
     * {@inheritdoc}
     */
    public function stopQuery()
    {
        $this->totalExecutionTime += $this->queryExecutionTimes[] = round(microtime(true) - $this->queryStartTime, 4) * 1000;
    }

    /**
     * Clean all collected data
     *
     * @return QueryAnalyzer
     */
    public function cleanUp()
    {
        $this->queryExecutionTimes = $this->queries = [];
        $this->totalExecutionTime  = 0;

        return $this;
    }

    /**
     * Dump the statistics of executed queries
     *
     * @param boolean $dumpOnlySql
     *
     * @return string
     */
    public function getOutput($dumpOnlySql = false)
    {
        $output = '';

        if (!$dumpOnlySql) {
            $output .= sprintf('Platform: %s%s', $this->platform->getName(), PHP_EOL);
            $output .= sprintf('Executed queries: %d, total time: %dms%s', count($this->queries), $this->totalExecutionTime, PHP_EOL);
        }

        foreach ($this->queries as $index => $sql) {
            if (!$dumpOnlySql) {
                $output .= sprintf('Query(%d) - %dms%', ($index + 1), $this->queryExecutionTimes[$index], PHP_EOL);
            }

            $output .= sprintf('%s;%s', $sql, PHP_EOL);
        }
        $output .= PHP_EOL;

        return $output;
    }

    /**
     * Index of the slowest query executed
     *
     * @return integer
     */
    public function getSlowestQueryIndex()
    {
        $slowest = $index = 0;

        foreach ($this->queryExecutionTimes as $i => $time) {
            if ($time > $slowest) {
                $slowest = $time;
                $index   = $i;
            }
        }

        return $index;
    }

    /**
     * Get total execution time of queries
     *
     * @return integer
     */
    public function getTotalExecutionTime()
    {
        return $this->totalExecutionTime;
    }

    /**
     * Get all queries
     *
     * @return array
     */
    public function getExecutedQueries()
    {
        return $this->queries;
    }

    /**
     * Get number of executed queries
     *
     * @return integer
     */
    public function getNumExecutedQueries()
    {
        return count($this->queries);
    }

    /**
     * Get all query execution times
     *
     * @return array
     */
    public function getExecutionTimes()
    {
        return $this->queryExecutionTimes;
    }

    /**
     * Create the SQL with mapped parameters
     *
     * @param string $sql
     * @param array  $params
     * @param array  $types
     *
     * @return string
     */
    private function generateSql($sql, $params, $types)
    {
        if (!count($params)) {
            return $sql;
        }

        $converted = $this->getConvertedParams($params, $types);

        if (is_int(key($params))) {
            $index = key($converted);
            $sql   = preg_replace_callback('@\?@sm', function ($match) use (&$index, $converted) {
                return $converted[$index++];
            }, $sql);
        } else {
            foreach ($converted as $key => $value) {
                $sql = str_replace(':' . $key, $value, $sql);
            }
        }

        return $sql;
    }

    /**
     * Get the converted parameter list
     *
     * @param array $params
     * @param array $types
     *
     * @return array
     */
    private function getConvertedParams($params, $types)
    {
        $result = [];

        foreach ($params as $position => $value) {
            if (isset($types[$position])) {
                $type = $types[$position];

                if (is_string($type)) {
                    $type = Type::getType($type);
                }

                if ($type instanceof Type) {
                    $value = $type->convertToDatabaseValue($value, $this->platform);
                }
            } else {
                if (is_object($value) && $value instanceof \DateTime) {
                    $value = $value->format($this->platform->getDateTimeFormatString());
                } elseif (null !== $value) {
                    $type  = Type::getType(gettype($value));
                    $value = $type->convertToDatabaseValue($value, $this->platform);
                }
            }

            if (is_string($value)) {
                $value = sprintf("'%s'", $value);
            } elseif (null === $value) {
                $value = 'NULL';
            }

            $result[$position] = $value;
        }

        return $result;
    }
}
