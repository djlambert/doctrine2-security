<?php

namespace CrEOF\Security\OwnedEntity;

use CrEOF\Security\AbstractTestCase;
use CrEOF\Security\OwnedEntity\EventSubscriber as OwnedEntityEventSubscriber;
use Doctrine\Common\EventManager;

/**
 * OwnedEntity extension mapping tests
 */
class MappingTest extends AbstractTestCase
{
    const OWNER            = 'Fixture\Owner';
    const ARTICLE          = 'OwnedEntity\Fixture\Article';
    const FEATURE          = 'OwnedEntity\Fixture\Feature';
    const PICTURE          = 'OwnedEntity\Fixture\Picture';
    const NO_OWNER_COLUMN  = 'OwnedEntity\Fixture\Bad\NoOwnerColumn';
    const NOT_OWNED_ENTITY = 'OwnedEntity\Fixture\Bad\NotOwnedEntity';
    const NO_OWNER_ASSOC   = 'OwnedEntity\Fixture\Bad\NoOwnerAssoc';

    /**
     * @var OwnedEntityEventSubscriber
     */
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
        return [];
    }

    /**
     * @test
     */
    public function nothingCached()
    {
        $config = $this->ownedEntityEventSubscriber->getConfiguration(self::ARTICLE, $this->entityManager);

        $this->assertEmpty($config);
    }

    /**
     * @test
     */
    public function cachedConfig()
    {
        $this->createEntitySchema($this->entityManager, [self::ARTICLE]);

        $expectedConfig = [
            'ownedEntity' => true,
            'ownerColumn' => 'owner',
            'useObjectClass' => 'OwnedEntity\Fixture\Article'
        ];

        $config = $this->ownedEntityEventSubscriber->getConfiguration(self::ARTICLE, $this->entityManager);

        $this->assertEquals($expectedConfig, $config);
    }

    /**
     * @test
     * @expectedException        \CrEOF\Security\Exception\InvalidMappingException
     * @expectedExceptionMessage OwnedEntity behavior requires OwnerColumn mapping
     */
    public function noOwnerColumn()
    {
        $this->createEntitySchema($this->entityManager, [self::NO_OWNER_COLUMN]);
    }

    /**
     * @test
     * @expectedException        \CrEOF\Security\Exception\InvalidMappingException
     * @expectedExceptionMessage ownerColumn mapping requires OwnedEntity behavior
     */
    public function notOwnedEntity()
    {
        $this->createEntitySchema($this->entityManager, [self::NOT_OWNED_ENTITY]);
    }

    /**
     * @test
     * @expectedException        \CrEOF\Security\Exception\InvalidMappingException
     * @expectedExceptionMessage OwnerColumn "owner" in entity "OwnedEntity\Fixture\Bad\NoOwnerAssoc" must have association mapped to entity containing owners
     */
    public function noOwnerAssoc()
    {
        $this->createEntitySchema($this->entityManager, [self::NO_OWNER_ASSOC]);
    }
}
