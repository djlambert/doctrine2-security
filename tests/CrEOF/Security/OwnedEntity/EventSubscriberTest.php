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
class EventSubscriberTest extends AbstractTestCase
{
    const OWNER         = 'Fixture\\Owner';
    const ARTICLE       = 'OwnedEntity\\Fixture\\Article';
    const FEATURE       = 'OwnedEntity\\Fixture\\Feature';
    const PICTURE       = 'OwnedEntity\\Fixture\\Picture';

    /**
     * @var OwnedEntityEventSubscriber
     */
    private $ownedEntityEventSubscriber;

    /**
     * Setup
     */
    protected function setUp()
    {
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
    public function persistTest()
    {
        $owner = new Owner();

        $owner->setUserName('joeuser')
            ->setFullName('Joe User');

        $this->entityManager->persist($owner);
        $this->ownedEntityEventSubscriber->setOwner($owner);

        $article = new Article;

        $article->setTitle('Joe\'s Article')
            ->setContent('This is my story');

        $this->entityManager->persist($article);

        $this->assertEquals($owner, $article->getOwner());
    }

    /**
     * @test
     */
    public function articleTest()
    {
        $owner = new Owner();

        $owner->setUserName('joeuser')
            ->setFullName('Joe User');
        $this->entityManager->persist($owner);
        $this->ownedEntityEventSubscriber->setOwner($owner);

        $article = new Article;

        $article->setTitle('Joe\'s Article')
            ->setContent('This is my story.');
        $this->entityManager->persist($article);
        $this->entityManager->flush();

        $articleId = $article->getId();

        $this->entityManager->clear();

        $article = $this->entityManager
            ->getRepository(self::ARTICLE)
            ->find($articleId);

        $newOwner = new Owner();

        $newOwner->setUserName('mr_smith')
            ->setFullName('Mike Smith');

        $this->entityManager->persist($newOwner);
        $this->ownedEntityEventSubscriber->setOwner($newOwner);
        $article->setContent('This is a story about Joe.');
        $this->entityManager->persist($article);
        $this->entityManager->flush();
        $this->entityManager->clear();

        $article = $this->entityManager
            ->getRepository(self::ARTICLE)
            ->find($articleId);

        $this->assertEquals($owner->getUserName(), $article->getOwner()->getUserName());
    }
}
