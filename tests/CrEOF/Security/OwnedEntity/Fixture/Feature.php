<?php

namespace OwnedEntity\Fixture;

use Doctrine\ORM\Mapping as ORM;
use CrEOF\Security\Mapping\Annotation as Security;

/**
 * Feature entity
 *
 * @ORM\Entity
 * @Security\OwnedEntity
 */
class Feature extends Article
{

}
