<?php

namespace OwnedEntity\Fixture\Bad;

use Doctrine\ORM\Mapping as ORM;
use CrEOF\Security\Mapping\Annotation as Security;

/**
 * Bad mapping entity - no owner column
 *
 * @ORM\Entity
 * @Security\OwnedEntity
 */
class NoOwnerColumn
{
    /**
     * @var integer
     *
     * @ORM\Id
     * @ORM\GeneratedValue
     * @ORM\Column(type="integer")
     */
    private $id;
}
