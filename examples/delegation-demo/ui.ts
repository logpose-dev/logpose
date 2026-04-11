import chalk from 'chalk';

export const ui = {
  runnerTag: chalk.gray('[Runner]'),
  agentATag: chalk.blueBright('[Agent A]'),
  agentBTag: chalk.magentaBright('[Agent B]'),

  step(text: string): string {
    return chalk.yellowBright.bold(text);
  },

  heading(text: string): string {
    return chalk.bold.cyanBright(text);
  },

  subheading(text: string): string {
    return chalk.gray(text);
  },

  success(text: string): string {
    return chalk.greenBright(text);
  },

  warning(text: string): string {
    return chalk.yellowBright(text);
  },

  error(text: string): string {
    return chalk.redBright(text);
  },

  label(text: string): string {
    return chalk.bold.white(text);
  },

  value(text: string): string {
    return chalk.cyanBright(text);
  },

  json(text: string): string {
    return chalk.gray(text);
  },

  trustBoolean(value: boolean): string {
    return value ? chalk.greenBright(String(value)) : chalk.redBright(String(value));
  },

  metric(value: number, positive = false): string {
    if (positive) {
      return value > 0 ? chalk.greenBright(String(value)) : chalk.white(String(value));
    }

    return value === 0 ? chalk.greenBright(String(value)) : chalk.redBright(String(value));
  },
};
