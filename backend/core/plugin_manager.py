import logging
import os
import json
import importlib.util
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class Plugin:
    def __init__(self, name: str, version: str, author: str, description: str):
        self.name = name
        self.version = version
        self.author = author
        self.description = description
        self.enabled = False
        self.config = {}
    
    def enable(self):
        self.enabled = True
        logger.info(f"Plugin '{self.name}' enabled")
    
    def disable(self):
        self.enabled = False
        logger.info(f"Plugin '{self.name}' disabled")
    
    def execute(self, *args, **kwargs) -> Dict[str, Any]:
        raise NotImplementedError


class PluginManager:
    def __init__(self, plugin_dir: str = None):
        self.plugins: Dict[str, Plugin] = {}
        self.plugin_dir = plugin_dir or os.path.join(os.path.dirname(__file__), 'plugins')
        self._load_builtin_plugins()
    
    def _load_builtin_plugins(self):
        self.plugins['threat_intel'] = ThreatIntelPlugin()
        self.plugins['firewall'] = FirewallPlugin()
        self.plugins['notification'] = NotificationPlugin()
        self.plugins['report_generator'] = ReportGeneratorPlugin()
        logger.info(f"Loaded {len(self.plugins)} builtin plugins")
    
    def register_plugin(self, plugin: Plugin) -> bool:
        if plugin.name in self.plugins:
            logger.warning(f"Plugin '{plugin.name}' already registered")
            return False
        self.plugins[plugin.name] = plugin
        return True
    
    def get_plugin(self, name: str) -> Optional[Plugin]:
        return self.plugins.get(name)
    
    def list_plugins(self) -> List[Dict[str, Any]]:
        return [
            {
                'name': p.name,
                'version': p.version,
                'author': p.author,
                'description': p.description,
                'enabled': p.enabled
            }
            for p in self.plugins.values()
        ]
    
    def enable_plugin(self, name: str) -> bool:
        plugin = self.plugins.get(name)
        if plugin:
            plugin.enable()
            return True
        return False
    
    def disable_plugin(self, name: str) -> bool:
        plugin = self.plugins.get(name)
        if plugin:
            plugin.disable()
            return True
        return False
    
    def execute_plugin(self, name: str, *args, **kwargs) -> Dict[str, Any]:
        plugin = self.plugins.get(name)
        if not plugin or not plugin.enabled:
            return {'error': f"Plugin '{name}' not found or disabled"}
        try:
            return plugin.execute(*args, **kwargs)
        except Exception as e:
            logger.error(f"Plugin '{name}' execution failed: {e}")
            return {'error': str(e)}


class ThreatIntelPlugin(Plugin):
    def __init__(self):
        super().__init__(
            name='threat_intel',
            version='1.0.0',
            author='SENTINEL',
            description='Enhanced threat intelligence with external feeds'
        )
        self.feeds = []
    
    def execute(self, *args, **kwargs) -> Dict[str, Any]:
        return {
            'threats_loaded': len(self.feeds),
            'last_update': datetime.utcnow().isoformat(),
            'status': 'active'
        }


class FirewallPlugin(Plugin):
    def __init__(self):
        super().__init__(
            name='firewall',
            version='1.0.0',
            author='SENTINEL',
            description='Advanced firewall rule management'
        )
        self.rules = []
    
    def execute(self, *args, **kwargs) -> Dict[str, Any]:
        action = kwargs.get('action', 'list')
        if action == 'list':
            return {'rules': self.rules, 'count': len(self.rules)}
        return {'status': 'processed'}


class NotificationPlugin(Plugin):
    def __init__(self):
        super().__init__(
            name='notification',
            version='1.0.0',
            author='SENTINEL',
            description='Multi-channel notifications (email, SMS, webhook)'
        )
        self.channels = ['log', 'webhook']
    
    def execute(self, *args, **kwargs) -> Dict[str, Any]:
        message = kwargs.get('message', '')
        channel = kwargs.get('channel', 'log')
        return {
            'sent': True,
            'channel': channel,
            'message': message,
            'timestamp': datetime.utcnow().isoformat()
        }


class ReportGeneratorPlugin(Plugin):
    def __init__(self):
        super().__init__(
            name='report_generator',
            version='1.0.0',
            author='SENTINEL',
            description='Generate security reports in multiple formats'
        )
        self.templates = ['summary', 'detailed', 'executive', 'vapt']
    
    def execute(self, *args, **kwargs) -> Dict[str, Any]:
        report_type = kwargs.get('type', 'summary')
        data = kwargs.get('data', {})
        return {
            'type': report_type,
            'generated_at': datetime.utcnow().isoformat(),
            'data': data,
            'status': 'ready'
        }


plugin_manager = PluginManager()
