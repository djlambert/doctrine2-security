<?php

namespace OwnedEntity\Fixture\Bad;

use Doctrine\ORM\Mapping as ORM;
use CrEOF\Security\Mapping\Annotation as Security;
use Fixture\Owner;

/**
 * Bad mapping entity - no association on owner column
 *
 * @ORM\Entity
 * @Security\OwnedEntity
 */
class NoOwnerAssoc
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
     * @Security\OwnerColumn
     */
    private $owner;
}
