"""
Copyright 2022 Veza Technologies Inc.

Use of this source code is governed by the MIT
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.
"""

from oaaclient.templates import OAAPermission

looker_permission_definitions = {
    "access_data": [OAAPermission.DataRead],
    "see_lookml_dashboards": [OAAPermission.DataRead],
    "see_looks": [OAAPermission.DataRead],
    "see_user_dashboards": [OAAPermission.DataRead],
    "explore": [OAAPermission.DataRead],
    "create_table_calculations": [OAAPermission.DataWrite],
    "save_content": [OAAPermission.DataWrite],
    "create_public_looks": [OAAPermission.DataWrite],
    "download_with_limit": [OAAPermission.DataRead],
    "download_without_limit": [OAAPermission.DataRead],
    "schedule_look_emails": [OAAPermission.NonData],
    "schedule_external_look_emails": [OAAPermission.NonData],
    "create_alerts": [OAAPermission.NonData],
    "follow_alerts": [OAAPermission.NonData],
    "send_to_s3": [OAAPermission.NonData],
    "send_to_sftp": [OAAPermission.NonData],
    "send_outgoing_webhook": [OAAPermission.NonData],
    "send_to_integration": [OAAPermission.NonData],
    "see_sql": [OAAPermission.NonData],
    "see_lookml": [OAAPermission.DataRead],
    "develop": [OAAPermission.DataRead, OAAPermission.DataWrite],
    "deploy": [OAAPermission.NonData],
    "support_access_toggle": [OAAPermission.NonData],
    "use_sql_runner": [OAAPermission.DataRead],
    "clear_cache_refresh": [OAAPermission.NonData],
    "see_drill_overlay": [OAAPermission.DataRead],
    "manage_spaces": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
    "manage_homepage": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
    "manage_models": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
    "manage_stereo": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
    "create_prefetches": [OAAPermission.NonData],
    "login_special_email": [OAAPermission.NonData],
    "embed_browse_spaces": [OAAPermission.NonData],
    "embed_save_shared_space": [OAAPermission.NonData],
    "see_alerts": [OAAPermission.MetadataRead],
    "see_queries": [OAAPermission.MetadataRead],
    "see_logs": [OAAPermission.MetadataRead],
    "see_users": [OAAPermission.MetadataRead],
    "sudo": [OAAPermission.NonData],
    "see_schedules": [OAAPermission.MetadataRead],
    "see_pdts": [OAAPermission.MetadataRead],
    "see_datagroups": [OAAPermission.MetadataRead],
    "update_datagroups": [OAAPermission.MetadataWrite],
    "see_system_activity": [OAAPermission.NonData],
    "administer": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite, OAAPermission.DataWrite, OAAPermission.DataRead],
    "mobile_app_access": [OAAPermission.NonData]
}
