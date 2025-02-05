import logging
import uuid
import sqlite3
import json
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional, Union
from pathlib import Path

# 配置日志模块
logging.basicConfig(
    level=logging.WARN,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class EntityType(IntEnum):
    """实体类型枚举"""
    FILE_PATH = 1
    REST_API = 2
    FUNCTION = 3
    SYSTEM_RESOURCE = 4

    @classmethod
    def get(cls, type_str: str) -> Optional['EntityType']:
        try:
            return cls[type_str.upper()]
        except KeyError:
            return None  

class RiskLevel(IntEnum):
    """风险等级体系"""
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    NONE = 0

    @classmethod
    def from_value(cls, value: int) -> 'RiskLevel':
        return cls(value) if value in cls._value2member_map_ else cls.NONE

class DatabaseManager:
    """增强的数据库管理类"""
    def __init__(self, db_path=':memory:'):
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.create_tables()

    def create_tables(self):
        """创建数据表结构"""
        with self.conn:
            self.conn.executescript('''
                CREATE TABLE IF NOT EXISTS projects (
                    project_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL
                );
                
                CREATE TABLE IF NOT EXISTS entities (
                    entity_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    type INTEGER NOT NULL,
                    metadata TEXT,
                    project_id TEXT NOT NULL,
                    FOREIGN KEY(project_id) REFERENCES projects(project_id) ON DELETE CASCADE
                );
                
                CREATE TABLE IF NOT EXISTS auto_risks (
                    risk_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_id TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    level INTEGER NOT NULL,
                    details TEXT NOT NULL,
                    FOREIGN KEY(entity_id) REFERENCES entities(entity_id) ON DELETE CASCADE
                );
                
                CREATE TABLE IF NOT EXISTS manual_risks (
                    risk_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_id TEXT NOT NULL,
                    description TEXT NOT NULL,
                    level INTEGER NOT NULL,
                    evidence TEXT NOT NULL,
                    FOREIGN KEY(entity_id) REFERENCES entities(entity_id) ON DELETE CASCADE
                );
            ''')

    # 项目操作
    def project_exists(self, project_id: str) -> bool:
        """检查项目是否存在"""
        cursor = self.conn.execute(
            'SELECT 1 FROM projects WHERE project_id = ?', 
            (project_id,)
        )
        return bool(cursor.fetchone())

    def upsert_project(self, project_id: str, name: str):
        """插入或更新项目"""
        with self.conn:
            self.conn.execute(
                'INSERT OR REPLACE INTO projects VALUES (?, ?)',
                (project_id, name)
            )

    # 实体操作
    def insert_entity(self, entity_id: str, name: str, entity_type: int, 
                     metadata: str, project_id: str):
        """插入新实体"""
        with self.conn:
            self.conn.execute(
                '''INSERT INTO entities 
                (entity_id, name, type, metadata, project_id)
                VALUES (?, ?, ?, ?, ?)''',
                (entity_id, name, entity_type, metadata, project_id)
            )

    def get_entity(self, entity_id: str) -> Optional[dict]:
        """获取单个实体"""
        cursor = self.conn.execute(
            'SELECT * FROM entities WHERE entity_id = ?', 
            (entity_id,)
        )
        return dict(cursor.fetchone()) if cursor.rowcount else None

    def find_entities(self, project_id: str, name: str = None, 
                     entity_type: int = None) -> List[dict]:
        """查找实体"""
        query = 'SELECT * FROM entities WHERE project_id = ?'
        params = [project_id]
        
        if name:
            query += ' AND name = ?'
            params.append(name)
        if entity_type is not None:
            query += ' AND type = ?'
            params.append(entity_type)
            
        cursor = self.conn.execute(query, params)
        return [dict(row) for row in cursor]

    def update_entity(self, entity_id: str, **kwargs):
        """
        更新实体信息
        :param entity_id: 要修改的实体ID
        :param kwargs: 可更新字段(name, type, metadata)
        """
        if not kwargs:
            return

        valid_fields = {'name', 'type', 'metadata'}
        updates = {k: v for k, v in kwargs.items() if k in valid_fields}
        if not updates:
            raise ValueError("没有有效的更新字段")

        set_clause = ", ".join([f"{k} = ?" for k in updates.keys()])
        values = list(updates.values())
        values.append(entity_id)

        with self.conn:
            self.conn.execute(
                f"UPDATE entities SET {set_clause} WHERE entity_id = ?",
                values
            )

    def delete_entity(self, entity_id: str):
        """删除实体及其所有关联风险"""
        with self.conn:
            self.conn.execute(
                "DELETE FROM entities WHERE entity_id = ?",
                (entity_id,)
            )        

    # 风险操作
    def insert_auto_risk(self, entity_id: str, rule_name: str, 
                        level: int, details: str):
        """插入自动检测风险"""
        with self.conn:
            self.conn.execute(
                '''INSERT INTO auto_risks 
                (entity_id, rule_name, level, details)
                VALUES (?, ?, ?, ?)''',
                (entity_id, rule_name, level, details)
            )

    def insert_manual_risk(self, entity_id: str, description: str,
                          level: int, evidence: str):
        """插入人工标记风险"""
        with self.conn:
            self.conn.execute(
                '''INSERT INTO manual_risks 
                (entity_id, description, level, evidence)
                VALUES (?, ?, ?, ?)''',
                (entity_id, description, level, evidence)
            )

    def get_entity_risks(self, entity_id: str) -> dict:
        """获取实体的所有风险"""
        risks = {'auto': [], 'manual': []}
        
        # 自动风险
        cursor = self.conn.execute(
            'SELECT * FROM auto_risks WHERE entity_id = ?',
            (entity_id,)
        )
        for row in cursor:
            risk = dict(row)
            risk['details'] = json.loads(risk['details'])
            risks['auto'].append(risk)
        
        # 人工风险
        cursor = self.conn.execute(
            'SELECT * FROM manual_risks WHERE entity_id = ?',
            (entity_id,)
        )
        for row in cursor:
            risks['manual'].append(dict(row))
            
        return risks

    def get_max_risk_level(self, project_id: str) -> int:
        """获取项目最大风险等级"""
        query = '''
            SELECT MAX(level) as max_level FROM (
                SELECT level FROM auto_risks
                WHERE entity_id IN (
                    SELECT entity_id FROM entities 
                    WHERE project_id = ?
                )
                UNION ALL
                SELECT level FROM manual_risks
                WHERE entity_id IN (
                    SELECT entity_id FROM entities 
                    WHERE project_id = ?
                )
            )
        '''
        cursor = self.conn.execute(query, (project_id, project_id))
        result = cursor.fetchone()
        return result['max_level'] if result['max_level'] is not None else 0

    def close(self):
        """关闭数据库连接"""
        self.conn.close()

class RiskSystem:
    """纯数据库驱动的风险管理系统"""
    def __init__(self, db_path='risk_system.db'):
        self.db = DatabaseManager(db_path)
        self.rules = self._init_rules()

    def _init_rules(self) -> list:
        return [
            {
                'name': 'sensitive_file',
                'condition': lambda e: "passwd" in e['name'].lower(),
                'description': "包含敏感信息的文件",
                'level': RiskLevel.CRITICAL,
                'target_types': [EntityType.FILE_PATH]
            },
            {
                'name': 'unsafe_delete_api',
                'condition': lambda e: json.loads(e['metadata']).get("method") == "DELETE",
                'description': "不安全的DELETE方法",
                'level': RiskLevel.HIGH,
                'target_types': [EntityType.REST_API]
            }
        ]

    def register_project(self, project_id: str, name: str):
        """注册项目"""
        self.db.upsert_project(project_id, name)

    def evaluate_entity(self, entity_id: str):
        """评估单个实体风险"""
        entity = self.db.get_entity(entity_id)
        if not entity:
            raise ValueError("实体不存在")

        entity_type = EntityType(entity['type'])
        metadata = json.loads(entity['metadata'])
        
        # 清空旧风险
        self._clear_auto_risks(entity_id)
        
        # 应用规则
        for rule in self.rules:
            if entity_type not in rule['target_types']:
                continue
                
            if rule['condition'](entity):
                risk_details = {
                    'description': rule['description'],
                    'evidence': self._collect_evidence(entity, metadata)
                }
                self.db.insert_auto_risk(
                    entity_id=entity_id,
                    rule_name=rule['name'],
                    level=rule['level'].value,
                    details=json.dumps(risk_details)
                )

    def _clear_auto_risks(self, entity_id: str):
        """清除自动风险记录"""
        with self.db.conn:
            self.db.conn.execute(
                'DELETE FROM auto_risks WHERE entity_id = ?',
                (entity_id,)
            )

    def _collect_evidence(self, entity: dict, metadata: dict) -> dict:
        """收集证据信息"""
        evidence = {'entity': entity['name']}
        entity_type = EntityType(entity['type'])
        
        if entity_type == EntityType.FILE_PATH:
            evidence['permission'] = metadata.get('permission', 'unknown')
        elif entity_type == EntityType.REST_API:
            evidence['method'] = metadata.get('method', 'GET')
            
        return evidence

    def add_manual_risk(self, entity_id: str, description: str,
                       level: Union[int, RiskLevel], evidence: str):
        """添加人工风险"""
        if isinstance(level, RiskLevel):
            level = level.value
        self.db.insert_manual_risk(
            entity_id=entity_id,
            description=description,
            level=level,
            evidence=evidence
        )

    def create_entity(self, project_id: str, name: str, 
                     entity_type: Union[str, EntityType], 
                     metadata: dict = None) -> str:
        """创建新实体"""
        if not self.db.project_exists(project_id):
            raise ValueError("项目不存在")
            
        if isinstance(entity_type, str):
            entity_type = EntityType[entity_type.upper()]
            
        entity_id = str(uuid.uuid4())
        self.db.insert_entity(
            entity_id=entity_id,
            name=name,
            entity_type=entity_type.value,
            metadata=json.dumps(metadata or {}),
            project_id=project_id
        )
        return entity_id

    def update_entity(
            self,
            entity_id: str,
            new_name: Optional[str] = None,
            new_type: Optional[Union[str, EntityType]] = None,
            new_metadata: Optional[dict] = None
        ) -> dict:
            """
            更新实体信息
            返回: {"success": bool, "message": str}
            """
            result = {"success": False, "message": ""}
            updates = {}

            try:
                # 验证实体存在
                if not self.db.get_entity(entity_id):
                    raise ValueError("实体不存在")

                # 处理名称更新
                if new_name is not None:
                    if not new_name.strip():
                        raise ValueError("实体名称不能为空")
                    updates["name"] = new_name

                # 处理类型更新
                if new_type is not None:
                    if isinstance(new_type, str):
                        if not EntityType.is_valid_type(new_type):
                            raise ValueError(f"无效实体类型: {new_type}")
                        new_type = EntityType[new_type.upper()]
                    updates["type"] = new_type.value

                # 处理元数据更新
                if new_metadata is not None:
                    try:
                        updates["metadata"] = json.dumps(new_metadata)
                    except TypeError:
                        raise ValueError("无效的元数据格式")

                if updates:
                    self.db.update_entity(entity_id, **updates)
                    # 如果修改了类型或元数据，需要重新评估风险
                    if "type" in updates or "metadata" in updates:
                        self.evaluate_entity(entity_id)

                    result["success"] = True
                    result["message"] = "实体更新成功"
                else:
                    result["message"] = "没有需要更新的内容"

            except Exception as e:
                result["message"] = str(e)
                logger.error(f"更新实体失败: {e}", exc_info=True)

            return result

    def delete_entity(self, entity_id: str) -> dict:
        """
        删除实体及其所有风险记录
        返回: {"success": bool, "message": str}
        """
        result = {"success": False, "message": ""}
        try:
            if not self.db.get_entity(entity_id):
                raise ValueError("实体不存在")

            self.db.delete_entity(entity_id)
            result["success"] = True
            result["message"] = "实体删除成功"
        except Exception as e:
            result["message"] = str(e)
            logger.error(f"删除实体失败: {e}", exc_info=True)
        return result   

    def batch_update_risks(
        self,
        conditions: dict,
        operation: str,
        operation_params: dict = None
    ) -> dict:
        """
        批量修改实体风险
        :param conditions: 筛选条件 {
            'project_id': str,           # 必填，项目ID
            'entity_type': str/int,      # 可选，实体类型
            'risk_type': 'auto/manual/all',  # 风险类型，默认all
            'min_level': int,            # 最低风险等级
            'max_level': int,            # 最高风险等级
            'rule_names': list,          # 规则名称列表（仅自动风险）
            'description_keywords': list # 描述关键词（仅手动风险）
        }
        :param operation: 操作类型 ['delete', 'update_level', 'add_manual']
        :param operation_params: 操作参数（根据操作类型不同）
        :return: {'success': bool, 'affected_rows': int, 'errors': list}
        """
        result = {'success': False, 'affected_rows': 0, 'errors': []}
        valid_operations = ['delete', 'update_level', 'add_manual']
        
        try:
            # 参数验证
            if not conditions.get('project_id'):
                raise ValueError("必须指定项目ID")
                
            if operation not in valid_operations:
                raise ValueError(f"无效操作类型，可选: {valid_operations}")

            # 获取符合条件的实体ID列表
            entity_ids = self._find_entities_by_conditions(conditions)
            if not entity_ids:
                return {**result, 'success': True, 'message': "没有符合条件的实体"}

            # 执行批量操作
            with self.db.conn:
                if operation == 'delete':
                    affected = self._batch_delete_risks(
                        entity_ids, conditions, operation_params
                    )
                elif operation == 'update_level':
                    affected = self._batch_update_risk_level(
                        entity_ids, conditions, operation_params
                    )
                elif operation == 'add_manual':
                    affected = self._batch_add_manual_risks(
                        entity_ids, operation_params
                    )

                result.update({
                    'success': True,
                    'affected_rows': affected,
                    'message': f"成功操作 {affected} 条风险记录"
                })

        except Exception as e:
            result['errors'].append(str(e))
            logger.error(f"批量操作失败: {e}", exc_info=True)
            
        return result

    def _find_entities_by_conditions(self, conditions: dict) -> List[str]:
        """根据条件查找实体ID列表"""
        query = '''
            SELECT entity_id FROM entities 
            WHERE project_id = ?
        '''
        params = [conditions['project_id']]
        
        # 实体类型筛选
        if conditions.get('entity_type'):
            entity_type = conditions['entity_type']
            if isinstance(entity_type, str):
                entity_type = EntityType[entity_type.upper()].value
            query += " AND type = ?"
            params.append(entity_type)
            
        # 执行查询
        cursor = self.db.conn.execute(query, params)
        return [row['entity_id'] for row in cursor]

    def _batch_delete_risks(
        self,
        entity_ids: List[str],
        conditions: dict,
        params: dict
    ) -> int:
        """批量删除风险"""
        risk_type = conditions.get('risk_type', 'all')
        clauses = []
        query_params = []

        # 风险等级筛选
        if conditions.get('min_level'):
            clauses.append("level >= ?")
            query_params.append(conditions['min_level'])
        if conditions.get('max_level'):
            clauses.append("level <= ?")
            query_params.append(conditions['max_level'])

        # 构建删除语句
        total_affected = 0
        queries = []
        
        if risk_type in ['auto', 'all']:
            auto_where = []
            auto_params = query_params.copy()
            
            # 规则名称筛选
            if conditions.get('rule_names'):
                placeholders = ','.join(['?']*len(conditions['rule_names']))
                auto_where.append(f"rule_name IN ({placeholders})")
                auto_params.extend(conditions['rule_names'])
                
            queries.append((
                'auto_risks',
                auto_where,
                auto_params
            ))

        if risk_type in ['manual', 'all']:
            manual_where = []
            manual_params = query_params.copy()
            
            # 描述关键词筛选
            if conditions.get('description_keywords'):
                kw_conditions = []
                for kw in conditions['description_keywords']:
                    kw_conditions.append("description LIKE ?")
                    manual_params.append(f"%{kw}%")
                manual_where.append("(" + " OR ".join(kw_conditions) + ")")
                
            queries.append((
                'manual_risks',
                manual_where,
                manual_params
            ))

        # 执行删除操作
        for table, where_clauses, params in queries:
            where = " AND ".join(where_clauses + clauses)
            if where:
                where = "WHERE " + where
            
            query = f'''
                DELETE FROM {table}
                WHERE entity_id IN ({','.join(['?']*len(entity_ids))})
                {where}
            '''
            final_params = entity_ids.copy()
            final_params.extend(params)
            
            cursor = self.db.conn.execute(query, final_params)
            total_affected += cursor.rowcount

        return total_affected

    def _batch_update_risk_level(
        self,
        entity_ids: List[str],
        conditions: dict,
        params: dict
    ) -> int:
        """批量更新风险等级"""
        if not params or 'new_level' not in params:
            raise ValueError("缺少new_level参数")
            
        new_level = params['new_level']
        if isinstance(new_level, RiskLevel):
            new_level = new_level.value
        elif not isinstance(new_level, int):
            raise ValueError("风险等级必须是整数或RiskLevel枚举")

        risk_type = conditions.get('risk_type', 'all')
        total_affected = 0

        # 更新自动风险
        if risk_type in ['auto', 'all']:
            query = '''
                UPDATE auto_risks 
                SET level = ?
                WHERE entity_id IN ({})
                AND level BETWEEN ? AND ?
            '''.format(','.join(['?']*len(entity_ids)))
            
            params = [
                new_level,
                conditions.get('min_level', 0),
                conditions.get('max_level', 4)
            ]
            if conditions.get('rule_names'):
                query += " AND rule_name IN ({})".format(
                    ','.join(['?']*len(conditions['rule_names']))
                )
                params.extend(conditions['rule_names'])
            
            cursor = self.db.conn.execute(query, entity_ids + params)
            total_affected += cursor.rowcount

        # 更新手动风险
        if risk_type in ['manual', 'all']:
            query = '''
                UPDATE manual_risks 
                SET level = ?
                WHERE entity_id IN ({})
                AND level BETWEEN ? AND ?
            '''.format(','.join(['?']*len(entity_ids)))
            
            params = [
                new_level,
                conditions.get('min_level', 0),
                conditions.get('max_level', 4)
            ]
            if conditions.get('description_keywords'):
                kw_conditions = []
                for kw in conditions['description_keywords']:
                    kw_conditions.append("description LIKE ?")
                    params.append(f"%{kw}%")
                query += " AND (" + " OR ".join(kw_conditions) + ")"
            
            cursor = self.db.conn.execute(query, entity_ids + params)
            total_affected += cursor.rowcount

        return total_affected

    def _batch_add_manual_risks(
        self,
        entity_ids: List[str],
        params: dict
    ) -> int:
        """批量添加手动风险"""
        required_fields = ['description', 'level', 'evidence']
        if not all(field in params for field in required_fields):
            raise ValueError("缺少必要参数: description, level, evidence")
            
        try:
            level = params['level']
            if isinstance(level, RiskLevel):
                level = level.value
            else:
                level = int(level)
        except ValueError:
            raise ValueError("无效的风险等级")

        data = [
            (eid, params['description'], level, params['evidence'])
            for eid in entity_ids
        ]
        
        cursor = self.db.conn.executemany('''
            INSERT INTO manual_risks 
            (entity_id, description, level, evidence)
            VALUES (?, ?, ?, ?)
        ''', data)
        
        return cursor.rowcount        

    def get_risk_report(self, project_id: str) -> dict:
        """生成风险报告"""
        if not self.db.project_exists(project_id):
            raise ValueError("项目不存在")
            
        max_level = self.db.get_max_risk_level(project_id)
        entities = self.db.find_entities(project_id)
        
        report = {
            'project_id': project_id,
            'max_risk_level': RiskLevel(max_level).name,
            'entities': []
        }
        
        for entity in entities:
            risks = self.db.get_entity_risks(entity['entity_id'])
            entity_report = {
                'entity_id': entity['entity_id'],
                'name': entity['name'],
                'type': EntityType(entity['type']).name,
                'total_risks': len(risks['auto']) + len(risks['manual']),
                'auto_risks': [{
                    'rule': r['rule_name'],
                    'level': RiskLevel(r['level']).name,
                    'details': r['details']
                } for r in risks['auto']],
                'manual_risks': [{
                    'description': r['description'],
                    'level': RiskLevel(r['level']).name,
                    'evidence': r['evidence']
                } for r in risks['manual']]
            }
            report['entities'].append(entity_report)
            
        return report

    def import_entities(self, project_id: str, file_path: Union[str, Path]):
        """从JSON文件导入实体"""
        file_path = Path(file_path)
        with file_path.open(encoding='utf-8') as f:
            entities = json.load(f)
            
        for item in entities:
            try:
                self.create_entity(
                    project_id=project_id,
                    name=item['name'],
                    entity_type=item['type'],
                    metadata=item.get('metadata')
                )
            except Exception as e:
                logger.error(f"导入失败: {str(e)}")

# 使用示例
if __name__ == "__main__":
    # 初始化系统
    system = RiskSystem("test.db")
    
    # 注册项目
    system.register_project("P1", "核心系统")
    
    # 创建实体
    entity_id = system.create_entity(
        project_id="P1",
        name="/etc/passwd",
        entity_type="FILE_PATH",
        metadata={"permission": 644}
    )
    
    # 评估风险
    system.evaluate_entity(entity_id)

    # 创建测试实体
    entity_id = system.create_entity(
        project_id="P1",
        name="old_name.txt",
        entity_type="FILE_PATH",
        metadata={"version": 1}
    )
    
    # 修改实体信息
    update_result = system.update_entity(
        entity_id=entity_id,
        new_name="new_name2.txt",
        new_metadata={"version": 2, "permission": 644}
    )
    print("更新结果:", update_result)
    
    # 验证修改
    entity = system.db.get_entity(entity_id)
    print("修改后的实体:", entity)

    # 添加人工风险
    system.add_manual_risk(
        entity_id=entity_id,
        description="人工标记风险",
        level=RiskLevel.HIGH,
        evidence="安全审计报告"
    )

           # 导入实体
    result = system.import_entities(
        project_id="P1",
        file_path="entities.json"
    )
    print(result)

    #将所有中高风险升级为低风险
    
    result = system.batch_update_risks(
        conditions={
            'project_id': 'P1',
            'min_level': RiskLevel.MEDIUM.value,
            'max_level': RiskLevel.HIGH.value
        },
        operation='update_level',
        operation_params={'new_level': RiskLevel.LOW}
    )
    print("更新结果:", result)
    
    # 生成报告
    #report = system.get_risk_report("P1")
    #print(json.dumps(report, indent=2, ensure_ascii=False))
    
    # 关闭连接
    system.db.close()
