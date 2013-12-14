<?php

namespace CrEOF\Security\Mapping;

use CrEOF\Security\AbstractTestCase;
use CrEOF\Security\OwnedEntity\EventSubscriber as OwnedEntityEventSubscriber;
use CrEOF\Security\Mapping\ExtensionMetadataFactory;
use Doctrine\Common\EventManager;
use Doctrine\Common\Util\Debug;
use Doctrine\ORM\Configuration;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\Tools\SchemaTool;
use OwnedEntity\Fixture\Article;

/**
 * Mapping tests
 */
class MappingTest extends \PHPUnit_Framework_TestCase
{
    const ARTICLE = 'OwnedEntity\\Fixture\\Article';

    /**
     * @var OwnedEntityEventSubscriber
     */
    private $ownedEntityEventSubscriber;

    private $entityManager;

    /**
     * Test setup
     */
    public function setUp()
    {
//        $config = new Configuration();
//
//        $config->setProxyDir($this->tempDir);
//        $config->setProxyNamespace('CrEOF\Security\Mapping\Proxy');
//        $config->setMetadataDriverImpl($this->getMetadataDriverImplementation());
//
//        $conn = [
//            'driver' => 'pdo_sqlite',
//            'memory' => true,
//        ];
//
//        $eventManager = new EventManager();
//
//        $eventManager->addEventSubscriber($this->ownedEntityEventSubscriber = new OwnedEntityEventSubscriber());
//
//        $this->eventManager = EntityManager::create($conn, $config, $eventManager);
//
//        $this->createEntitySchema($this->eventManager);
        $config = new Configuration();
        $config->setProxyDir(__DIR__ . '/../../temp');
        $config->setProxyNamespace('CrEOF\Security\Mapping\Proxy');
        //$this->markTestSkipped('Skipping according to a bug in annotation reader creation.');
        $config->setMetadataDriverImpl(new \Doctrine\ORM\Mapping\Driver\AnnotationDriver($_ENV['annotation_reader']));

        $conn = [
            'driver' => 'pdo_sqlite',
            'memory' => true,
        ];

        $eventManager = new \Doctrine\Common\EventManager();
        $eventManager->addEventSubscriber($this->ownedEntityEventSubscriber = new OwnedEntityEventSubscriber());
        $this->entityManager = \Doctrine\ORM\EntityManager::create($conn, $config, $eventManager);

        $schemaTool = new \Doctrine\ORM\Tools\SchemaTool($this->entityManager);
        $schemaTool->dropSchema([]);
        $schemaTool->createSchema([
            $this->entityManager->getClassMetadata(self::ARTICLE),
        ]);

    }

    public function testNoCacheImplementationMapping()
    {
        $article = new Article;
        $article->setTitle('test');
        $this->entityManager->persist($article);
        $this->entityManager->flush();

        $configuration = $this->ownedEntityEventSubscriber->getConfiguration(self::ARTICLE, $this->entityManager);

        $this->assertCount(0, $configuration);
    }

    protected function getUsedEntityFixtures()
    {
        return [
            self::ARTICLE
        ];
    }
}
