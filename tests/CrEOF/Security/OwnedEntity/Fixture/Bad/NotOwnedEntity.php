<?php

namespace OwnedEntity\Fixture\Bad;

use Doctrine\ORM\Mapping as ORM;
use CrEOF\Security\Mapping\Annotation as Security;
use Fixture\Owner;

/**
 * Bad mapping entity - not owned entity
 *
 * @ORM\Entity
 */
class NotOwnedEntity
{
    /**
     * @var integer
     *
     * @ORM\Id
     * @ORM\GeneratedValue
     * @ORM\Column(type="integer")
     */
    private $id;

    /**
     * @var Owner
     *
     * @ORM\ManyToOne(targetEntity="Fixture\Owner")
     * @ORM\JoinColumn(name="owner_id", referencedColumnName="id")
     * @Security\OwnerColumn
     */
    private $owner;
}
