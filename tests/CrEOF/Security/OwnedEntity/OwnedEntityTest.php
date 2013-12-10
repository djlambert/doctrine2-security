<?php

namespace CrEOF\Security\OwnedEntity;

use CrEOF\Security\OwnedEntity\EventSubscriber;
use Tool\AbstractTestCase;
use Fixture\Owner;
use OwnedEntity\Fixture\Article;
use Doctrine\ORM\Mapping\Driver\DriverChain;
use Doctrine\ORM\Mapping\Driver\SimplifiedXmlDriver;
use Doctrine\ORM\Mapping\Driver\AnnotationDriver;
use Doctrine\Common\EventManager;

/**
 * OwnedEntity behavior tests
 */
class OwnedEntityTest extends AbstractTestCase
{
    const OWNER         = 'Fixture\\Owner';
    const ARTICLE       = 'OwnedEntity\\Fixture\\Article';

    private $eventSubscriber;
    private $entityListener;
    /**
     * Setup
     */
    protected function setUp()
    {
        parent::setUp();

        $evm                   = new EventManager;
        $this->eventSubscriber = new EventSubscriber();

        $evm->addEventSubscriber($this->eventSubscriber);
        $this->getMockSqliteEntityManager($evm);

        $this->entityListener = $this->em->getConfiguration()
            ->getEntityListenerResolver()
            ->resolve('CrEOF\Security\OwnedEntity\EntityListener');

    }

    /**
     * {@inheritDoc}
     */
    protected function getUsedEntityFixtures()
    {
        return [
            self::OWNER,
            self::ARTICLE
        ];
    }

    /**
     * @test
     */
    public function articleTest()
    {
        $repo = $this->em->getRepository(self::ARTICLE);

        $article = new Article;
        $article->setTitle('test');
        $this->em->persist($article);
        $this->em->flush();
    }
}
