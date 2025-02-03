import logging
import uuid
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional, Union
from collections import defaultdict
import json
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
        """安全获取枚举值"""
        try:
            return cls[type_str.upper()]
        except KeyError:
            return None  

    @classmethod
    def is_valid_type(cls, type_str: str) -> bool:
        return type_str.upper() in cls._member_names_              

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

class Entity:
    """实体对象"""
    def __init__(
        self,
        name: str,
        entity_type: EntityType,
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.entity_id = str(uuid.uuid4())
        self.name = name
        self.type = entity_type
        self.metadata = metadata or {}

    def __repr__(self) -> str:
        return f"<{self.type.name} {self.name}>"

class EntityRisk:
    """实体风险评估"""
    def __init__(self, entity: Entity):
        self.entity = entity
        self.auto_risks = []
        self.manual_risks = []

    def add_auto_risk(self, rule_name: str, level: RiskLevel, details: dict):
        self.auto_risks.append({
            "type": "auto",
            "rule": rule_name,
            "level": level,
            "details": details
        })

    def add_manual_risk(self, description: str, level: RiskLevel, evidence: str):
        self.manual_risks.append({
            "type": "manual",
            "description": description,
            "level": level,
            "evidence": evidence
        })

    @property
    def all_risks(self) -> List[dict]:
        return self.auto_risks + self.manual_risks

    @property
    def max_risk_level(self) -> RiskLevel:
        if not self.all_risks:
            return RiskLevel.NONE
        return max((r["level"] for r in self.all_risks), default=RiskLevel.NONE)

    def get_detailed_report(self) -> dict:
        return {
            "entity_id": self.entity.entity_id,
            "name": self.entity.name,
            "type": self.entity.type.name,
            "risk_level": self.max_risk_level.name,
            "total_risks": len(self.all_risks),
            "auto_risks": self.auto_risks,
            "manual_risks": self.manual_risks
        }

class Project:
    """项目管理"""
    def __init__(self, project_id: str, name: str):
        self.project_id = project_id
        self.name = name
        self.entities = {}  # {entity_id: Entity}
        self.risks = {}     # {entity_id: EntityRisk}

    def add_entity(self, entity: Entity) -> None:
        self.entities[entity.entity_id] = entity

    def update_risk(self, entity_id: str, risk: EntityRisk) -> None:
        self.risks[entity_id] = risk

    @property
    def overall_risk(self) -> RiskLevel:
        if not self.risks:
            return RiskLevel.NONE
        return max((r.max_risk_level for r in self.risks.values()), default=RiskLevel.NONE)

    def get_full_report(self) -> dict:
        return {
            "project_info": {
                "id": self.project_id,
                "name": self.name,
                "overall_risk": self.overall_risk.name
            },
            "entities": [r.get_detailed_report() for r in self.risks.values()]
        }

    def find_entities_by_name_type(
        self, 
        name: str, 
        entity_type: EntityType
    ) -> List[Entity]:
        """根据名称和类型查找实体"""
        return [
            e for e in self.entities.values()
            if e.name == name and e.type == entity_type
        ]        

class RiskRule:
    """风险规则"""
    def __init__(
        self,
        name: str,
        condition: Callable[[Entity], bool],
        description: str,
        level: RiskLevel,
        target_types: List[EntityType]
    ):
        self.name = name
        self.condition = condition
        self.description = description
        self.level = level
        self.target_types = target_types

class RiskSystem:
    """风险管理系统"""
    def __init__(self):
        self.projects = {}
        self.rules = self._init_rules()

    def _init_rules(self) -> List[RiskRule]:
        return [
            RiskRule(
                name="sensitive_file",
                condition=lambda e: "passwd" in e.name.lower(),
                description="包含敏感信息的文件",
                level=RiskLevel.CRITICAL,
                target_types=[EntityType.FILE_PATH]
            ),
            RiskRule(
                name="unsafe_delete_api",
                condition=lambda e: e.metadata.get("method") == "DELETE",
                description="不安全的DELETE方法",
                level=RiskLevel.HIGH,
                target_types=[EntityType.REST_API]
            )
        ]

    def register_project(self, project: Project) -> None:
        self.projects[project.project_id] = project

    def evaluate_entity(self, entity: Entity) -> EntityRisk:
        risk = EntityRisk(entity)
        for rule in self.rules:
            if entity.type in rule.target_types and rule.condition(entity):
                risk.add_auto_risk(
                    rule.name,
                    rule.level,
                    {
                        "description": rule.description,
                        "evidence": self._collect_evidence(entity)
                    }
                )
        return risk

    def _collect_evidence(self, entity: Entity) -> dict:
        evidence = {"entity": entity.name}
        if entity.type == EntityType.FILE_PATH:
            evidence["permission"] = entity.metadata.get("permission", "unknown")
        elif entity.type == EntityType.REST_API:
            evidence["method"] = entity.metadata.get("method", "GET")
        return evidence

    def evaluate_project(self, project_id: str) -> None:
        project = self.projects.get(project_id)
        if not project:
            return

        for entity in project.entities.values():
            risk = self.evaluate_entity(entity)
            project.update_risk(entity.entity_id, risk)

    def add_manual_risk(
        self,
        project_id: str,
        entity_id: str,
        description: str,
        level: RiskLevel,
        evidence: str
    ) -> None:
        project = self.projects.get(project_id)
        if project and entity_id in project.risks:
            project.risks[entity_id].add_manual_risk(description, level, evidence)

    def add_manual_risk_by_name_type(
            self,
            project_id: str,
            entity_name: str,
            entity_type: Union[str, EntityType],
            description: str,
            level: Union[int, RiskLevel],
            evidence: str
        ) -> dict:
            """
            通过实体名称和类型添加手动风险
            返回: {success: 成功数量, failed: 失败原因列表}
            """
            project = self.projects.get(project_id)
            result = {"success": 0, "failed": []}
            
            # 校验项目存在性
            if not project:
                result["failed"].append("项目不存在")
                return result

            # 类型安全转换
            try:
                if isinstance(entity_type, str):
                    entity_type = EntityType[entity_type.upper()]
                if isinstance(level, int):
                    level = RiskLevel.from_value(level)
            except KeyError:
                result["failed"].append(f"无效实体类型: {entity_type}")
                return result
            except ValueError:
                result["failed"].append(f"无效风险等级: {level}")
                return result

            # 查找匹配实体
            matched_entities = project.find_entities_by_name_type(entity_name, entity_type)
            if not matched_entities:
                result["failed"].append(f"未找到实体: {entity_name}({entity_type.name})")
                return result

            # 批量添加风险
            for entity in matched_entities:
                try:
                    self.add_manual_risk(
                        project_id=project_id,
                        entity_id=entity.entity_id,
                        description=description,
                        level=level,
                        evidence=evidence
                    )
                    result["success"] += 1
                except Exception as e:
                    result["failed"].append(f"实体 {entity.entity_id} 添加失败: {str(e)}")
                    logger.error(f"添加风险失败: {e}", exc_info=True)

            return result

    def import_entities_from_json(
            self,
            project_id: str,
            json_path: Union[str, Path],
            overwrite: bool = False
        ) -> dict:
            """
            从JSON文件批量导入实体到指定项目
            :param project_id: 目标项目ID
            :param json_path: JSON文件路径
            :param overwrite: 是否覆盖已有同名实体
            :return: 导入结果 {added: 新增数量, skipped: 跳过数量, errors: 错误列表}
            """
            project = self.projects.get(project_id)
            if not project:
                raise ValueError(f"项目 {project_id} 不存在")

            if isinstance(json_path, str):
                json_path = Path(json_path)

            result = {"added": 0, "skipped": 0, "errors": []}
            
            try:
                with json_path.open('r', encoding='utf-8') as f:
                    entities_data = json.load(f)
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                result["errors"].append(f"JSON解析失败: {str(e)}")
                return result
            except FileNotFoundError:
                result["errors"].append(f"文件不存在: {json_path}")
                return result

            for idx, data in enumerate(entities_data, 1):
                try:
                    # 类型转换校验
                    entity_type = EntityType[data["type"].upper()]
                    
                    # 名称查重逻辑
                    existing = next(
                        (e for e in project.entities.values() 
                        if e.name == data["name"] and e.type == entity_type),
                        None
                    )
                    
                    if existing and not overwrite:
                        result["skipped"] += 1
                        logger.info(f"跳过重复实体: {data['name']}")
                        continue
                        
                    # 创建新实体
                    entity = Entity(
                        name=data["name"],
                        entity_type=entity_type,
                        metadata=data.get("metadata", {})
                    )
                    project.add_entity(entity)
                    result["added"] += 1

                    # 自动评估风险
                    risk = self.evaluate_entity(entity)
                    project.update_risk(entity.entity_id, risk)

                except KeyError as e:
                    error_msg = f"条目{idx}: 缺少必要字段 {str(e)}"
                    result["errors"].append(error_msg)
                    logger.warning(error_msg)
                except Exception as e:
                    error_msg = f"条目{idx}: 处理失败 - {str(e)}"
                    result["errors"].append(error_msg)
                    logger.error(error_msg, exc_info=True)

            logger.info(f"导入完成: 新增 {result['added']} 实体，跳过 {result['skipped']} 项")
            return result

# 测试用例
if __name__ == "__main__":
    # 初始化系统
    system = RiskSystem()

    # 创建项目
    project = Project("P1", "核心系统")
    
    # 创建实体
    file_entity = Entity(
        name="/etc/passwd",
        entity_type=EntityType.FILE_PATH,
        metadata={"permission": 644}
    )
    
    api_entity = Entity(
        name="/api/users",
        entity_type=EntityType.REST_API,
        metadata={"method": "DELETE"}
    )

    # 添加实体到项目
    project.add_entity(file_entity)
    project.add_entity(api_entity)
    
    # 注册项目并评估
    system.register_project(project)
    system.evaluate_project("P1")

    # 导入实体
    result = system.import_entities_from_json(
        project_id="P1",
        json_path="entities.json",
        overwrite=True
    )

    # 添加手动风险
    system.add_manual_risk(
        project_id="P1",
        entity_id=file_entity.entity_id,
        description="人工标记的配置风险",
        level=RiskLevel.HIGH,
        evidence="安全审计报告第5章"
    )

    # 通过名称类型添加风险
    result = system.add_manual_risk_by_name_type(
        project_id="P1",
        entity_name="/api/admin2",
        entity_type="REST_API",  # 支持字符串或枚举
        description="接口无认证",
        level=RiskLevel.HIGH,     # 支持枚举或整数值
        evidence="CIS标准第3.1章"
    )

    print(f"操作结果: {result}")

    result = system.add_manual_risk_by_name_type(
        project_id="P1",
        entity_name="/api/admin2",
        entity_type="REST_API",  # 支持字符串或枚举
        description="接口无认证xx",
        level=RiskLevel.HIGH,     # 支持枚举或整数值
        evidence="CIS标准第3.1章"
    )

    # 生成报告
    report = project.get_full_report()

    # 打印详细报告
    def print_detailed_report(report: dict):
        """格式化打印报告"""
        print(f"\n{' 项目风险评估报告 ':=^60}")
        print(f"项目名称: {report['project_info']['name']}")
        print(f"整体风险等级: {report['project_info']['overall_risk']}")
        
        print("\n实体详细风险分析:")
        for entity in report['entities']:
            print(f"\n■ 实体名称: {entity['name']}")
            print(f"  类型: {entity['type']}")
            print(f"  风险等级: {entity['risk_level']}")
            print(f"  总风险项: {entity['total_risks']}")
            
            print("\n  自动检测风险:")
            for risk in entity['auto_risks']:
                print(f"  - [规则] {risk['rule']}")
                print(f"    等级: {risk['level'].name}")
                print(f"    描述: {risk['details']['description']}")
                print(f"    证据: {risk['details']['evidence']}")
            
            print("\n  人工标记风险:")
            for risk in entity['manual_risks']:
                print(f"  - {risk['description']}")
                print(f"    等级: {risk['level'].name}")
                print(f"    依据: {risk['evidence']}")

    print_detailed_report(report)
