<?php

namespace CrEOF\Security\OwnedEntity;

use CrEOF\Security\AbstractTestCase;
use CrEOF\Security\OwnedEntity\EventSubscriber as OwnedEntityEventSubscriber;
use Fixture\Owner;
use OwnedEntity\Fixture\Article;
use Doctrine\Common\EventManager;

/**
 * OwnedEntity behavior tests
 */
class OwnedEntityTest extends AbstractTestCase
{
    const OWNER         = 'Fixture\\Owner';
    const ARTICLE       = 'OwnedEntity\\Fixture\\Article';
    const FEATURE       = 'OwnedEntity\\Fixture\\Feature';
    const PICTURE       = 'OwnedEntity\\Fixture\\Picture';

    private $ownedEntityEventSubscriber;

    /**
     * Setup
     */
    protected function setUp()
    {
        parent::setUp();

        $eventManager                     = new EventManager;
        $this->ownedEntityEventSubscriber = new OwnedEntityEventSubscriber();

        $eventManager->addEventSubscriber($this->ownedEntityEventSubscriber);

        $this->getMockSqliteEntityManager($eventManager);
    }

    /**
     * {@inheritDoc}
     */
    protected function getUsedEntityFixtures()
    {
        return [
            self::OWNER,
            self::ARTICLE,
            self::FEATURE,
            self::PICTURE
        ];
    }

    /**
     * @test
     */
    public function articleTest()
    {
//        $repo = $this->entityManager->getRepository(self::ARTICLE);
//
//        $owner = new Owner();
//        $this->entityManager->persist($owner);
//
//        $article = new Article;
//        $article->setTitle('test');
//        $this->entityManager->persist($article);
//        $this->entityManager->flush();
//
//        $this->entityManager->clear();
    }
}
