<?php

namespace CrEOF\Security;

use CrEOF\Security\OwnedEntity\EventSubscriber as OwnedEntityEventSubscriber;
use CrEOF\Security\Tool\Logging\DBAL\QueryAnalyzer;
use Doctrine\Common\EventManager;
use Doctrine\Common\Annotations\AnnotationReader;
use Doctrine\Common\Annotations\CachedReader;
use Doctrine\Common\Annotations\Reader;
use Doctrine\Common\Cache\ArrayCache;
use Doctrine\ORM\Configuration;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\Mapping\Driver\AnnotationDriver;
use Doctrine\ORM\Mapping\DefaultQuoteStrategy;
use Doctrine\ORM\Mapping\DefaultNamingStrategy;
use Doctrine\ORM\Repository\DefaultRepositoryFactory;
use Doctrine\ORM\Tools\SchemaTool;

/**
 * Common test code
 */
abstract class AbstractTestCase extends \PHPUnit_Framework_TestCase
{
    /**
     * @var Reader
     */
    static protected $annotationReader;

    /**
     * @var string
     */
    protected $tempDir;

    /**
     * @var EntityManager
     */
    protected $entityManager;

    /**
     * @var QueryAnalyzer
     */
    protected $queryAnalyzer;

    /**
     * Constructor
     *
     * Set shared properties
     */
    public function __construct()
    {
        $this->tempDir = __DIR__ . '/../../temp';
    }

    /**
     * Get a list of used fixture classes
     *
     * @return array
     */
    abstract protected function getUsedEntityFixtures();

    /**
     * {@inheritDoc}
     */
    protected function setUp()
    {

    }

    /**
     * EntityManager mock object together with annotation mapping driver and pdo_sqlite database in memory
     *
     * @param EventManager  $eventManager
     * @param Configuration $config
     *
     * @return EntityManager
     */
    protected function getMockSqliteEntityManager(EventManager $eventManager = null, Configuration $config = null)
    {
        $config = null === $config ? $this->getMockAnnotatedConfig() : $config;
        $conn   = [
            'driver' => 'pdo_sqlite',
            'memory' => true,
        ];

        return $this->getMockEntityManager($conn, $config, $eventManager);
    }

    /**
     * EntityManager mock object together with annotation mapping driver and custom connection
     *
     * @param array        $conn
     * @param EventManager $eventManager
     *
     * @return EntityManager
     */
    protected function getMockCustomEntityManager(array $conn, EventManager $eventManager = null)
    {
        return $this->getMockEntityManager($conn, $this->getMockAnnotatedConfig(), $eventManager);
    }

    /**
     * @param array         $conn
     * @param Configuration $config
     * @param EventManager  $eventManager
     *
     * @return EntityManager
     */
    protected function getMockEntityManager(array $conn, Configuration $config = null, EventManager $eventManager = null)
    {
        $entityManager = EntityManager::create($conn, $config, $eventManager ?: $this->getEventManager());

        $this->createEntitySchema($entityManager);

        return $this->entityManager = $entityManager;
    }

    /**
     * EntityManager mock object with annotation mapping driver
     *
     * @param EventManager $eventManager
     *
     * @return EntityManager
     */
    protected function getMockMappedEntityManager(EventManager $eventManager = null)
    {
        $driver = $this->getMock('Doctrine\DBAL\Driver');

        $driver->expects($this->once())
            ->method('getDatabasePlatform')
            ->will($this->returnValue($this->getMock('Doctrine\DBAL\Platforms\MySqlPlatform')));

        $conn = $this->getMock('Doctrine\DBAL\Connection', [], [[], $driver]);

        $conn->expects($this->once())
            ->method('getEventManager')
            ->will($this->returnValue($eventManager ?: $this->getEventManager()));

        return $this->entityManager = EntityManager::create($conn, $this->getMockAnnotatedConfig());
    }

    /**
     * @param EntityManager $entityManager
     * @param array         $classes
     *
     * @return array
     */
    protected function getEntityMetadata(EntityManager $entityManager, array $classes = [])
    {
        $getClassMetadata = function ($class) use ($entityManager) {
            return $entityManager->getClassMetadata($class);
        };

        return array_map($getClassMetadata, (array) $classes ?: $this->getUsedEntityFixtures());
    }

    /**
     * @param EntityManager $entityManager
     * @param array         $classes
     */
    protected function createEntitySchema(EntityManager $entityManager, array $classes = [])
    {
        $schemaTool = new SchemaTool($entityManager);

        $schemaTool->dropSchema([]);
        $schemaTool->createSchema($this->getEntityMetadata($entityManager, $classes));
    }

    /**
     * Creates default mapping driver
     *
     * @return AnnotationDriver
     */
    protected function getMetadataDriverImplementation()
    {
        if (null === static::$annotationReader) {
            static::$annotationReader = new CachedReader(new AnnotationReader(), new ArrayCache());
        }

        return new AnnotationDriver(static::$annotationReader);
    }

    /**
     * Starts query statistic log
     *
     * @throws \RuntimeException
     */
    protected function startQueryLog()
    {
        if ( ! $this->entityManager || ! $this->entityManager->getConnection()->getDatabasePlatform()) {
            throw new \RuntimeException('EntityManager and database platform must be initialized');
        }

        $this->queryAnalyzer = new QueryAnalyzer($this->entityManager->getConnection()->getDatabasePlatform());

        $this->entityManager
            ->getConfiguration()
            ->expects($this->any())
            ->method('getSQLLogger')
            ->will($this->returnValue($this->queryAnalyzer));
    }

    /**
     * Stops query statistic log and outputs the data to screen or file
     *
     * @param bool $dumpOnlySql
     * @param bool $writeToLog
     *
     * @throws \RuntimeException
     */
    protected function stopQueryLog($dumpOnlySql = false, $writeToLog = false)
    {
        if ($this->queryAnalyzer) {
            $output = $this->queryAnalyzer->getOutput($dumpOnlySql);

            if ($writeToLog) {
                $fileName = $this->tempDir . '/query_debug_' . time() . '.log';

                if (($file = fopen($fileName, 'w+')) !== false) {
                    fwrite($file, $output);
                    fclose($file);
                } else {
                    throw new \RuntimeException('Unable to write to the log file');
                }
            } else {
                echo $output;
            }
        }
    }

    /**
     * Get annotation mapping configuration
     *
     * @return \Doctrine\ORM\Configuration
     */
    protected function getMockAnnotatedConfig()
    {
        // We need to mock every method except the ones which handle the filters
        $configClass      = 'Doctrine\ORM\Configuration';
        $configReflection = new \ReflectionClass($configClass);
        $configMethods    = $configReflection->getMethods();

        $mockMethods = [];

        foreach ($configMethods as $method) {
            if ($method->name !== 'addFilter' && $method->name !== 'getFilterClassName') {
                $mockMethods[] = $method->name;
            }
        }

        $config = $this->getMock($configClass, $mockMethods);

        $config
            ->expects($this->once())
            ->method('getProxyDir')
            ->will($this->returnValue($this->tempDir));

        $config
            ->expects($this->once())
            ->method('getProxyNamespace')
            ->will($this->returnValue('Proxy'));

        $config
            ->expects($this->once())
            ->method('getAutoGenerateProxyClasses')
            ->will($this->returnValue(true));

        $config
            ->expects($this->once())
            ->method('getClassMetadataFactoryName')
            ->will($this->returnValue('Doctrine\\ORM\\Mapping\\ClassMetadataFactory'));

        $config
            ->expects($this->any())
            ->method('getMetadataDriverImpl')
            ->will($this->returnValue($this->getMetadataDriverImplementation()));

        $config
            ->expects($this->any())
            ->method('getDefaultRepositoryClassName')
            ->will($this->returnValue('Doctrine\\ORM\\EntityRepository'));

        $config
            ->expects($this->any())
            ->method('getQuoteStrategy')
            ->will($this->returnValue(new DefaultQuoteStrategy));

        $config
            ->expects($this->any())
            ->method('getNamingStrategy')
            ->will($this->returnValue(new DefaultNamingStrategy));

        $config
            ->expects($this->once())
            ->method('getRepositoryFactory')
            ->will($this->returnValue(new DefaultRepositoryFactory));

        return $config;
    }

    /**
     * Build event manager
     *
     * @return EventManager
     */
    private function getEventManager()
    {
        $eventManager = new EventManager;

        $eventManager->addEventSubscriber(new OwnedEntityEventSubscriber());

        return $eventManager;
    }
}
