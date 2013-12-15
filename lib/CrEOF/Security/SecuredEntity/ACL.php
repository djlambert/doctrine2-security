<?php

class ACL
{
    const ACL_SUPPORT_ALLOW_ACL    = 0x00000001;
    const ACL_SUPPORT_DENY_ACL     = 0x00000002;
    const ACL_SUPPORT_AUDIT_ACL    = 0x00000004;
    const ACL_SUPPORT_ALARM_ACL    = 0x00000008;

    protected $ACEs = [];

}
