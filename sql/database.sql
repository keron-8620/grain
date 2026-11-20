-- grain 初始化数据
--
-- 使用顺序：
--   1) grain -conf config/config.yaml -migrate          # 建表
--   2) grain -conf config/config.yaml -exec-sql sql/database.sql
--   3) grain -conf config/config.yaml -bootstrap-admin  # 生成一次性随机口令并打印
--   4) grain -conf config/config.yaml                   # 启动服务
--
-- 说明：
--   * 本文件不创建任何默认账号。初始管理员必须通过 -bootstrap-admin 创建；
--     该命令生成随机口令且只打印一次，服务启动时会拒绝仍使用历史默认口令的账号。
--   * 本文件只应在全新的数据库上执行一次；重复执行会因唯一索引冲突而失败。
--   * 脚本给 admin 角色授予当前全部 API 权限；后续新增的路由需在角色管理中补授权。
--   * 兼容 SQLite / MySQL / PostgreSQL。SQL Server 不支持 TRUE 字面量，需改为 1。
--   * 菜单/按钮数据未预置，可按前端路由在“菜单管理”中维护。
--   * 如执行时报错，请确认已先运行 -migrate；-exec-sql 会把本文件放在单个事务中执行。


INSERT INTO iam_role (name, descr, created_at, updated_at)
VALUES ('admin', '超级管理员', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO iam_api (url, method, label, descr, created_at, updated_at) VALUES
('/api/v1/apis', 'GET', '/api/v1/apis', 'grain/internal/service/iam.(*Service).ListApis-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/apis', 'POST', '/api/v1/apis', 'grain/internal/service/iam.(*Service).CreateApi-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/apis/:id', 'DELETE', '/api/v1/apis/:id', 'grain/internal/service/iam.(*Service).DeleteApi-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/apis/:id', 'GET', '/api/v1/apis/:id', 'grain/internal/service/iam.(*Service).GetApi-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/apis/:id', 'PUT', '/api/v1/apis/:id', 'grain/internal/service/iam.(*Service).UpdateApi-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/apis/sync', 'POST', '/api/v1/apis/sync', 'grain/internal/service/iam.(*Service).SyncApis-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/auth/login', 'POST', '/api/v1/auth/login', 'grain/internal/service/iam.(*Service).Login-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/auth/logout', 'POST', '/api/v1/auth/logout', 'grain/internal/service/iam.(*Service).Logout-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/auth/me', 'GET', '/api/v1/auth/me', 'grain/internal/service/iam.(*Service).GetProfile-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/auth/refresh', 'POST', '/api/v1/auth/refresh', 'grain/internal/service/iam.(*Service).RefreshToken-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/buttons', 'GET', '/api/v1/buttons', 'grain/internal/service/iam.(*Service).ListButtons-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/buttons', 'POST', '/api/v1/buttons', 'grain/internal/service/iam.(*Service).CreateButton-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/buttons/:id', 'DELETE', '/api/v1/buttons/:id', 'grain/internal/service/iam.(*Service).DeleteButton-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/buttons/:id', 'GET', '/api/v1/buttons/:id', 'grain/internal/service/iam.(*Service).GetButton-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/buttons/:id', 'PUT', '/api/v1/buttons/:id', 'grain/internal/service/iam.(*Service).UpdateButton-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/hosts', 'GET', '/api/v1/hosts', 'grain/internal/service/cmdb.(*Service).ListHosts-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/hosts', 'POST', '/api/v1/hosts', 'grain/internal/service/cmdb.(*Service).CreateHost-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/hosts/:id', 'DELETE', '/api/v1/hosts/:id', 'grain/internal/service/cmdb.(*Service).DeleteHost-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/hosts/:id', 'GET', '/api/v1/hosts/:id', 'grain/internal/service/cmdb.(*Service).GetHost-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/hosts/:id', 'PUT', '/api/v1/hosts/:id', 'grain/internal/service/cmdb.(*Service).UpdateHost-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/hosts/:id/refresh-key', 'POST', '/api/v1/hosts/:id/refresh-key', 'grain/internal/service/cmdb.(*Service).RefreshHostKey-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/menus', 'GET', '/api/v1/menus', 'grain/internal/service/iam.(*Service).ListMenus-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/menus', 'POST', '/api/v1/menus', 'grain/internal/service/iam.(*Service).CreateMenu-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/menus/:id', 'DELETE', '/api/v1/menus/:id', 'grain/internal/service/iam.(*Service).DeleteMenu-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/menus/:id', 'GET', '/api/v1/menus/:id', 'grain/internal/service/iam.(*Service).GetMenu-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/menus/:id', 'PUT', '/api/v1/menus/:id', 'grain/internal/service/iam.(*Service).UpdateMenu-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/menus/tree', 'GET', '/api/v1/menus/tree', 'grain/internal/service/iam.(*Service).GetMenuTree-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/public-key', 'GET', '/api/v1/public-key', 'grain/internal/service/iam.(*Service).GetPublicKey-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/roles', 'GET', '/api/v1/roles', 'grain/internal/service/iam.(*Service).ListRoles-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/roles', 'POST', '/api/v1/roles', 'grain/internal/service/iam.(*Service).CreateRole-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/roles/:id', 'DELETE', '/api/v1/roles/:id', 'grain/internal/service/iam.(*Service).DeleteRole-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/roles/:id', 'GET', '/api/v1/roles/:id', 'grain/internal/service/iam.(*Service).GetRole-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/roles/:id', 'PUT', '/api/v1/roles/:id', 'grain/internal/service/iam.(*Service).UpdateRole-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/schedules', 'GET', '/api/v1/schedules', 'grain/internal/service/job.(*Service).ListSchedules-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/schedules', 'POST', '/api/v1/schedules', 'grain/internal/service/job.(*Service).CreateSchedule-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/schedules/:id', 'DELETE', '/api/v1/schedules/:id', 'grain/internal/service/job.(*Service).DeleteSchedule-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/schedules/:id', 'GET', '/api/v1/schedules/:id', 'grain/internal/service/job.(*Service).GetSchedule-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/schedules/:id', 'PUT', '/api/v1/schedules/:id', 'grain/internal/service/job.(*Service).UpdateSchedule-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/schedules/:id/disable', 'POST', '/api/v1/schedules/:id/disable', 'grain/internal/service/job.(*Service).DisableSchedule-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/schedules/:id/enable', 'POST', '/api/v1/schedules/:id/enable', 'grain/internal/service/job.(*Service).EnableSchedule-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/schedules/:id/run', 'POST', '/api/v1/schedules/:id/run', 'grain/internal/service/job.(*Service).RunSchedule-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/script-records', 'GET', '/api/v1/script-records', 'grain/internal/service/job.(*Service).ListScriptRecords-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/script-records', 'POST', '/api/v1/script-records', 'grain/internal/service/job.(*Service).CreateScriptRecord-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/script-records/:id', 'GET', '/api/v1/script-records/:id', 'grain/internal/service/job.(*Service).GetScriptRecord-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/script-records/:id/cancel', 'POST', '/api/v1/script-records/:id/cancel', 'grain/internal/service/job.(*Service).CancelScriptRecord-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/script-records/:id/log', 'GET', '/api/v1/script-records/:id/log', 'grain/internal/service/job.(*Service).DownloadScriptRecordLog-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/scripts', 'GET', '/api/v1/scripts', 'grain/internal/service/job.(*Service).ListScripts-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/scripts', 'POST', '/api/v1/scripts', 'grain/internal/service/job.(*Service).CreateScript-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/scripts/:id', 'DELETE', '/api/v1/scripts/:id', 'grain/internal/service/job.(*Service).DeleteScript-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/scripts/:id', 'GET', '/api/v1/scripts/:id', 'grain/internal/service/job.(*Service).GetScript-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/scripts/:id', 'PUT', '/api/v1/scripts/:id', 'grain/internal/service/job.(*Service).UpdateScript-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/scripts/:id/content', 'GET', '/api/v1/scripts/:id/content', 'grain/internal/service/job.(*Service).GetScriptContent-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/users', 'GET', '/api/v1/users', 'grain/internal/service/iam.(*Service).ListUsers-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/users', 'POST', '/api/v1/users', 'grain/internal/service/iam.(*Service).CreateUser-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/users/:id', 'DELETE', '/api/v1/users/:id', 'grain/internal/service/iam.(*Service).DeleteUser-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/users/:id', 'GET', '/api/v1/users/:id', 'grain/internal/service/iam.(*Service).GetUser-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/users/:id', 'PUT', '/api/v1/users/:id', 'grain/internal/service/iam.(*Service).UpdateUser-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/users/:id/change-password', 'POST', '/api/v1/users/:id/change-password', 'grain/internal/service/iam.(*Service).ChangePassword-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('/api/v1/users/:id/reset-password', 'POST', '/api/v1/users/:id/reset-password', 'grain/internal/service/iam.(*Service).ResetPassword-fm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

-- 将当前全部 API 授权给 admin 角色
INSERT INTO iam_role_api (role_id, api_id)
SELECT r.id, a.id FROM iam_role r, iam_api a WHERE r.name = 'admin';
