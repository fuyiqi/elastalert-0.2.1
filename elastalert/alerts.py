# -*- coding: utf-8 -*-
import copy
import json
import os

from staticconf.loader import yaml_loader
from texttable import Texttable

from .util import EAException
from .util import elastalert_logger
from .util import filter_special_characters
from .util import lookup_es_key
from .util import resolve_string
from .util import send_WS


class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, 'isoformat'):
            return obj.isoformat()
        else:
            return json.JSONEncoder.default(self, obj)


class BasicMatchString(object):
    """ Creates a string containing fields in match for the given rule. """

    def __init__(self, rule, match):
        self.rule = rule
        self.match = match

    def _ensure_new_line(self):
        while self.text[-2:] != '\n\n':
            self.text += '\n'

    def _add_custom_alert_text(self):
        missing = self.rule.get('alert_missing_value', 'MISSING_VALUE')
        alert_text = str(self.rule.get('alert_text', ''))

        if 'alert_text_args' in self.rule:
            alert_text_args = self.rule.get('alert_text_args')
            alert_text_values = [lookup_es_key(self.match, arg) for arg in alert_text_args]

            # Support referencing other top-level rule properties
            # This technically may not work if there is a top-level rule property with the same name
            # as an es result key, since it would have been matched in the lookup_es_key call above
            for i, text_value in enumerate(alert_text_values):
                if text_value is None:
                    alert_value = self.rule.get(alert_text_args[i])
                    if alert_value:
                        alert_text_values[i] = alert_value

            alert_text_values = [missing if val is None else val for val in alert_text_values]
            alert_text = alert_text.format(*alert_text_values)
        elif 'alert_text_kw' in self.rule:
            kw = {}
            for name, kw_name in list(self.rule.get('alert_text_kw').items()):
                val = lookup_es_key(self.match, name)

                # Support referencing other top-level rule properties
                # This technically may not work if there is a top-level rule property with the same name
                # as an es result key, since it would have been matched in the lookup_es_key call above
                if val is None:
                    val = self.rule.get(name)

                kw[kw_name] = missing if val is None else val
            alert_text = alert_text.format(**kw)
        self.text += alert_text

    def _add_rule_text(self):
        self.text += self.rule['type'].get_match_str(self.match)

    def _add_top_counts(self):
        for key, counts in list(self.match.items()):
            if key.startswith('top_events_'):
                self.text += '%s:\n' % (key[11:])
                top_events = list(counts.items())

                if not top_events:
                    self.text += 'No events found.\n'
                else:
                    top_events.sort(key=lambda x: x[1], reverse=True)
                    for term, count in top_events:
                        self.text += '%s: %s\n' % (term, count)

                self.text += '\n'

    def _add_match_items(self):
        match_items = list(self.match.items())
        match_items.sort(key=lambda x: x[0])
        for key, value in match_items:
            if key.startswith('top_events_'):
                continue
            value_str = str(value)
            value_str.replace('\\n', '\n')
            if type(value) in [list, dict]:
                try:
                    value_str = self._pretty_print_as_json(value)
                except TypeError:
                    # Non serializable object, fallback to str
                    pass
            self.text += '%s: %s\n' % (key, value_str)

    def _pretty_print_as_json(self, blob):
        try:
            return json.dumps(blob, cls=DateTimeEncoder, sort_keys=True, indent=4, ensure_ascii=False)
        except UnicodeDecodeError:
            # This blob contains non-unicode, so lets pretend it's Latin-get-pip.py to show something
            return json.dumps(blob, cls=DateTimeEncoder, sort_keys=True, indent=4, encoding='Latin-get-pip.py',
                              ensure_ascii=False)

    # fyq addding
    def custom_alert_text(self):
        missing = self.rule.get('alert_missing_value', 'MISSING_VALUE')
        alert_text = str(self.rule.get('alert_text', ''))

        if 'alert_text_args' in self.rule:
            alert_text_args = self.rule.get('alert_text_args')
            alert_text_values = [lookup_es_key(self.match, arg) for arg in alert_text_args]

            for i, text_value in enumerate(alert_text_values):
                if text_value is None:
                    alert_value = self.rule.get(alert_text_args[i])
                    if alert_value:
                        alert_text_values[i] = alert_value

            alert_text_values = [missing if val is None else val for val in alert_text_values]
            alert_text = alert_text.format(*alert_text_values)
        elif 'alert_text_kw' in self.rule:
            kw = {}
            for name, kw_name in list(self.rule.get('alert_text_kw').items()):
                val = lookup_es_key(self.match, name)

                if val is None:
                    val = self.rule.get(name)

                kw[kw_name] = missing if val is None else val
            elastalert_logger.info(
                "[BasicMatchString.custom_alert_text()]raw alert_text={}===================".format(alert_text))  # 缺内容的壳子
            elastalert_logger.info(
                "[BasicMatchString.custom_alert_text()]kw={}\n=======================".format(kw))  # 壳子的内容
            alert_text = alert_text.format(**kw)
        return alert_text, kw

    # fyq added

    def __str__(self):
        self.text = ''
        if 'alert_text' not in self.rule:
            self.text += self.rule['name'] + '\n\n'

        self._add_custom_alert_text()
        self._ensure_new_line()
        if self.rule.get('alert_text_type') != 'alert_text_only':
            self._add_rule_text()
            self._ensure_new_line()
            if self.rule.get('top_count_keys'):
                self._add_top_counts()
            if self.rule.get('alert_text_type') != 'exclude_fields':
                self._add_match_items()
        return self.text




class Alerter(object):
    """ Base class for types of alerts.

    :param rule: The rule configuration.
    """
    required_options = frozenset([])

    def __init__(self, rule):
        self.rule = rule
        # pipeline object is created by ElastAlerter.send_alert()
        # and attached to each alerters used by a rule before calling alert()
        self.pipeline = None
        self.resolve_rule_references(self.rule)

    def resolve_rule_references(self, root):
        # Support referencing other top-level rule properties to avoid redundant copy/paste
        if type(root) == list:
            # Make a copy since we may be modifying the contents of the structure we're walking
            for i, item in enumerate(copy.copy(root)):
                if type(item) == dict or type(item) == list:
                    self.resolve_rule_references(root[i])
                else:
                    root[i] = self.resolve_rule_reference(item)
        elif type(root) == dict:
            # Make a copy since we may be modifying the contents of the structure we're walking
            for key, value in root.copy().items():
                if type(value) == dict or type(value) == list:
                    self.resolve_rule_references(root[key])
                else:
                    root[key] = self.resolve_rule_reference(value)

    def resolve_rule_reference(self, value):
        strValue = str(value)
        if strValue.startswith('$') and strValue.endswith('$') and strValue[1:-1] in self.rule:
            if type(value) == int:
                return int(self.rule[strValue[1:-1]])
            else:
                return self.rule[strValue[1:-1]]
        else:
            return value

    def alert(self, match):
        """ Send an alert. Match is a dictionary of information about the alert.

        :param match: A dictionary of relevant information to the alert.
        """
        raise NotImplementedError()

    def get_info(self):
        """ Returns a dictionary of data related to this alert. At minimum, this should contain
        a field type corresponding to the type of Alerter. """
        return {'type': 'Unknown'}

    def create_title(self, matches):
        """ Creates custom alert title to be used, e.g. as an e-mail subject or JIRA issue summary.

        :param matches: A list of dictionaries of relevant information to the alert.
        """
        if 'alert_subject' in self.rule:
            return self.create_custom_title(matches)

        return self.create_default_title(matches)

    def create_custom_title(self, matches):
        alert_subject = str(self.rule['alert_subject'])
        alert_subject_max_len = int(self.rule.get('alert_subject_max_len', 2048))

        if 'alert_subject_args' in self.rule:
            alert_subject_args = self.rule['alert_subject_args']
            alert_subject_values = [lookup_es_key(matches[0], arg) for arg in alert_subject_args]

            # Support referencing other top-level rule properties
            # This technically may not work if there is a top-level rule property with the same name
            # as an es result key, since it would have been matched in the lookup_es_key call above
            for i, subject_value in enumerate(alert_subject_values):
                if subject_value is None:
                    alert_value = self.rule.get(alert_subject_args[i])
                    if alert_value:
                        alert_subject_values[i] = alert_value

            missing = self.rule.get('alert_missing_value', 'MISSING_VALUE')
            alert_subject_values = [missing if val is None else val for val in alert_subject_values]
            alert_subject = alert_subject.format(*alert_subject_values)

        if len(alert_subject) > alert_subject_max_len:
            alert_subject = alert_subject[:alert_subject_max_len]

        return alert_subject

    def create_alert_body(self, matches):
        body = self.get_aggregation_summary_text(matches)
        if self.rule.get('alert_text_type') != 'aggregation_summary_only':
            for match in matches:
                body += str(BasicMatchString(self.rule, match))
                # Separate text of aggregated alerts with dashes
                if len(matches) > 1:
                    body += '\n----------------------------------------\n'
        return body

    def get_aggregation_summary_text__maximum_width(self):
        """Get maximum width allowed for summary text."""
        return 80

    def get_aggregation_summary_text(self, matches):
        text = ''
        if 'aggregation' in self.rule and 'summary_table_fields' in self.rule:
            text = self.rule.get('summary_prefix', '')
            summary_table_fields = self.rule['summary_table_fields']
            if not isinstance(summary_table_fields, list):
                summary_table_fields = [summary_table_fields]
            # Include a count aggregation so that we can see at a glance how many of each aggregation_key were encountered
            summary_table_fields_with_count = summary_table_fields + ['count']
            text += "Aggregation resulted in the following data for summary_table_fields ==> {0}:\n\n".format(
                summary_table_fields_with_count
            )
            text_table = Texttable(max_width=self.get_aggregation_summary_text__maximum_width())
            text_table.header(summary_table_fields_with_count)
            # Format all fields as 'text' to avoid long numbers being shown as scientific notation
            text_table.set_cols_dtype(['t' for i in summary_table_fields_with_count])
            match_aggregation = {}

            # Maintain an aggregate count for each unique key encountered in the aggregation period
            for match in matches:
                key_tuple = tuple([str(lookup_es_key(match, key)) for key in summary_table_fields])
                if key_tuple not in match_aggregation:
                    match_aggregation[key_tuple] = 1
                else:
                    match_aggregation[key_tuple] = match_aggregation[key_tuple] + 1
            for keys, count in match_aggregation.items():
                text_table.add_row([key for key in keys] + [count])
            text += text_table.draw() + '\n\n'
            text += self.rule.get('summary_prefix', '')
        return str(text)

    def create_default_title(self, matches):
        return self.rule['name']

    def get_account(self, account_file):
        """ Gets the username and password from an account file.

        :param account_file: Path to the file which contains user and password information.
        It can be either an absolute file path or one that is relative to the given rule.
        """
        if os.path.isabs(account_file):
            account_file_path = account_file
        else:
            account_file_path = os.path.join(os.path.dirname(self.rule['rule_file']), account_file)
        account_conf = yaml_loader(account_file_path)
        if 'user' not in account_conf or 'password' not in account_conf:
            raise EAException('Account file must have user and password fields')
        self.user = account_conf['user']
        self.password = account_conf['password']



class DebugAlerter(Alerter):
    """ The debug alerter uses a Python logger (by default, alerting to terminal).
    不实际进行告警发送,将匹配到的告警打印到终端
    """

    def alert(self, matches):
        qk = self.rule.get('query_key', None)
        for match in matches:  # match是命中的hits具体内容
            if qk in match:
                elastalert_logger.info(
                    '[alerts.DebugAlerter.alert()]match_rulename= %s;query_key= %s;match_time= %s'
                    % (self.rule['name'], match[qk], lookup_es_key(match, self.rule['timestamp_field'])))
            else:
                elastalert_logger.info('[alerts.DebugAlerter.alert()]match_rulename= %s;match_time= %s'
                                       % (self.rule['name'], lookup_es_key(match, self.rule['timestamp_field'])))
            elastalert_logger.info('[alerts.DebugAlerter.alert()] BasicMatchString.__str__()= %s'
                                   % (BasicMatchString(self.rule, match)))

    def get_info(self):
        return {'type': 'debug'}


'''fyq deleting
class CommandAlerter(Alerter):
    required_options = set(['command'])

    def __init__(self, *args):
        super(CommandAlerter, self).__init__(*args)

        self.last_command = []

        self.shell = False
        if isinstance(self.rule['command'], str):
            self.shell = True
            if '%' in self.rule['command']:
                elastalert_logger.warning('[alerts.CommandAlerter.__init__()]Warning! You could be vulnerable to shell injection!')
            self.rule['command'] = [self.rule['command']]

        self.new_style_string_format = False
        if 'new_style_string_format' in self.rule and self.rule['new_style_string_format']:
            self.new_style_string_format = True

    def alert(self, matches):
        # Format the command and arguments
        try:
            command = [resolve_string(command_arg, matches[0]) for command_arg in self.rule['command']]
            self.last_command = command
        except KeyError as e:
            elastalert_logger.error("[alerts.CommandAlerter.alert()]Error formatting command= %s" % (e),
                                    exc_info=True)
            raise EAException("[alerts.CommandAlerter.alert()]Error formatting command= %s" % (e))

        # Run command and pipe data
        try:
            # 调子进程
            subp = subprocess.Popen(command, stdin=subprocess.PIPE, shell=self.shell)

            if self.rule.get('pipe_match_json'):
                match_json = json.dumps(matches, cls=DateTimeEncoder) + '\n'
                stdout, stderr = subp.communicate(input=match_json)
            elif self.rule.get('pipe_alert_text'):
                alert_text = self.create_alert_body(matches)
                stdout, stderr = subp.communicate(input=alert_text)
            if self.rule.get("fail_on_non_zero_exit", False) and subp.wait():
                elastalert_logger.error("[alerts.CommandAlerter.alert()]Non-zero exit code while running command %s" % (' '.join(command)),
                                        exc_info=True)
                raise EAException("[alerts.CommandAlerter.alert()]Non-zero exit code while running command %s" % (' '.join(command)))
        except OSError as e:
            elastalert_logger.error("[alerts.CommandAlerter.alert()]Error while running command %s: %s" % (' '.join(command), e),
                                    exc_info=True)
            raise EAException("[alerts.CommandAlerter.alert()]Error while running command %s: %s" % (' '.join(command), e))

    def get_info(self):
        return {'type': 'command',
                'command': ' '.join(self.last_command)}
'''  # fyq deleted


# fyq updating
class CommandAlerter(Alerter):
    required_options = set(['command'])

    def __init__(self, *args):
        super(CommandAlerter, self).__init__(*args)

        self.last_command = []

        self.shell = False
        if isinstance(self.rule['command'], str):
            self.shell = True
            if '%' in self.rule['command']:
                elastalert_logger.warning(
                    '[alerts.CommandAlerter.__init__()]Warning! You could be vulnerable to shell injection!')
            self.rule['command'] = [self.rule['command']]

        self.new_style_string_format = False
        if 'new_style_string_format' in self.rule and self.rule['new_style_string_format']:
            self.new_style_string_format = True

    def alert(self, matches):
        # 格式化command和参数
        try:
            command = [resolve_string(command_arg, matches[0]) for command_arg in self.rule['command']]
            self.last_command = command
        except KeyError as e:
            elastalert_logger.error("[alerts.CommandAlerter.alert()]Error formatting command= %s" % (e),
                                    exc_info=True)
            raise EAException("[alerts.CommandAlerter.alert()]Error formatting command= %s" % (e))
        # 添加个性化告警详情
        custom_alert_text, cat_dict = BasicMatchString(self.rule, matches[0]).custom_alert_text()
        # 发送
        try:
            # 是否解析出命中主机,ip
            isHostValid = cat_dict['host'] != 'MISSING_VALUE'
            isIPValid = cat_dict['ip'] != 'MISSING_VALUE'
            elastalert_logger.info("[CommandAlerter.alert()]isHostValid=%s,;isIPValid=%s".format(isHostValid,isIPValid))
            if isIPValid:  # ip可用
                host = cat_dict['ip']
            else:  # ip不可用
                if isHostValid:  # host可用
                    host = cat_dict['host']
                else:  # host不可用
                    host = command[2]  # 默认配置
            instance = command[3]
            parameter = command[4]
            Class = command[5]
            status = command[6]
            # 是否展示个性化告警详情
            if (custom_alert_text):
                value = custom_alert_text
                elastalert_logger.info("[CommandAlerter.alert()]custom_alert_text=%s", value)
            else:
                value = filter_special_characters(command[7])
            elastalert_logger.info("[CommandAlerter.alert()]alert_text=%s", value)
            alarmTitle = filter_special_characters(command[8])
            elastalert_logger.info("[CommandAlerter.alert()]prepare sendWS_param\n" +
                                   ">>>>>>>>>> host=%s \n" +
                                   ">>>>>>>>>> instance=%s\n" +
                                   ">>>>>>>>>> parameter=%s\n" +
                                   ">>>>>>>>>> Class=%s\n" +
                                   ">>>>>>>>>> status=%s\n" +
                                   ">>>>>>>>>> value%s\n" +
                                   ">>>>>>>>>> alarmTitle", host, instance, parameter, Class, status, value, alarmTitle)
            send_WS(host=host, instance=instance, parameter=parameter, Class=Class, status=status, value=value,
                    alarmTitle=alarmTitle)
        except Exception as e:
            elastalert_logger.error('[alerts.CommandAlerter.alert()]error= %s;command= %s' % (e, command))

    def get_info(self):
        return {'type': 'command',
                'command': ' '.join(self.last_command)}


# fyq updated

