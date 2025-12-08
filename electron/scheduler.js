const schedule = require('node-schedule');
const database = require('./database');

class TaskScheduler {
  constructor() {
    this.jobs = new Map();
  }

  initialize() {
    // Load active tasks from database and schedule them
    const tasks = database.query(
      'SELECT * FROM scheduled_tasks WHERE is_active = 1'
    );
    
    tasks.forEach(task => {
      this.scheduleTask(task);
    });
  }

  scheduleTask(task) {
    try {
      // Parse the schedule (cron format)
      const job = schedule.scheduleJob(task.schedule, () => {
        this.executeTask(task);
      });
      
      this.jobs.set(task.id, job);
      
      return {
        success: true,
        taskId: task.id,
        message: 'Task scheduled successfully'
      };
    } catch (error) {
      return {
        success: false,
        message: 'Failed to schedule task: ' + error.message
      };
    }
  }

  executeTask(task) {
    console.log(`Executing task ${task.id}: ${task.task_type}`);
    
    // Task execution logic will be implemented based on task_type
    // Examples:
    // - 'threat_scan': Run automated threat scan
    // - 'network_scan': Run network device scan
    // - 'backup': Backup encrypted vault
    
    // For now, just log the execution
    // TODO: Implement actual task execution based on task_type
  }

  cancelTask(taskId) {
    const job = this.jobs.get(taskId);
    
    if (job) {
      job.cancel();
      this.jobs.delete(taskId);
      
      // Update database
      database.run(
        'UPDATE scheduled_tasks SET is_active = 0 WHERE id = ?',
        [taskId]
      );
      
      return {
        success: true,
        message: 'Task cancelled successfully'
      };
    }
    
    return {
      success: false,
      message: 'Task not found'
    };
  }

  getTasks(userId = null) {
    const query = userId
      ? 'SELECT * FROM scheduled_tasks WHERE user_id = ?'
      : 'SELECT * FROM scheduled_tasks';
    
    const params = userId ? [userId] : [];
    
    return database.query(query, params);
  }

  createTask(userId, taskType, schedule, config = null) {
    try {
      const result = database.run(
        'INSERT INTO scheduled_tasks (user_id, task_type, schedule, config) VALUES (?, ?, ?, ?)',
        [userId, taskType, schedule, JSON.stringify(config)]
      );
      
      const task = {
        id: result.lastInsertRowid,
        user_id: userId,
        task_type: taskType,
        schedule: schedule,
        config: JSON.stringify(config),
        is_active: 1
      };
      
      this.scheduleTask(task);
      
      return {
        success: true,
        taskId: task.id,
        message: 'Task created and scheduled'
      };
    } catch (error) {
      return {
        success: false,
        message: 'Failed to create task: ' + error.message
      };
    }
  }

  shutdown() {
    // Cancel all jobs
    this.jobs.forEach(job => job.cancel());
    this.jobs.clear();
  }
}

module.exports = new TaskScheduler();
