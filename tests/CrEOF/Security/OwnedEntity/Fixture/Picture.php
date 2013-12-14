<?php

namespace OwnedEntity\Fixture;

use Doctrine\ORM\Mapping as ORM;
use CrEOF\Security\Mapping\Annotation as Security;
use Fixture\Owner;

/**
 * Picture entity
 *
 * @ORM\Entity
 * @Security\OwnedEntity
 */
class Picture
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
     * @var string
     *
     * @ORM\Column(type="string")
     */
    private $title;

    /**
     * @var string
     *
     * @ORM\Column(type="text", nullable=true)
     */
    private $image;

    /**
     * @var Owner
     *
     * @ORM\ManyToOne(targetEntity="Fixture\Owner")
     * @ORM\JoinColumn(name="owner_id", referencedColumnName="id")
     * @Security\OwnerColumn
     */
    private $owner;

    /**
     * Get id
     *
     * @return int
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * Set image
     *
     * @param mixed $image
     *
     * @return self
     */
    public function setImage($image)
    {
        $this->image = $image;

        return $this;
    }

    /**
     * Get image
     *
     * @return mixed
     */
    public function getImage()
    {
        return $this->image;
    }

    /**
     * Set title
     *
     * @param mixed $title
     *
     * @return self
     */
    public function setTitle($title)
    {
        $this->title = $title;

        return $this;
    }

    /**
     * Get title
     *
     * @return mixed
     */
    public function getTitle()
    {
        return $this->title;
    }
}
