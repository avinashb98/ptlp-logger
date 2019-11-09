const winston = require('winston');

class ExpressLogger {
    constructor(httpContext, service) {
        this.service = service;
        this.setLogLevels();
        this.logLevel = this.getLogLevel();
        this.winstonLogger = winston.createLogger({
            levels: winston.config.syslog.levels,
            transports: [
                new winston.transports.Console({
                    level: this.logLevel,
                    showLevel: false,
                }),
            ],
            exitOnError: false,
        });

        this.httpContext = httpContext;
    }

    setup() {
        return (req, res, next) => {
            // bind httpContext to req and res
            this.httpContext.ns.bindEmitter(req);
            this.httpContext.ns.bindEmitter(res);
            // add request id and request start time to context
            this.httpContext.set('request-id', req.headers['request-id']);
            this.httpContext.set('request-start-time', Date.now());

            // Updating service counter in the header;
            const counter = req.headers['Service-Counter'] ? req.headers['Service-Counter'] : 0;
            req.headers['Service-Counter'] = counter + 1;

            // log request
            if (this.logLevel === 'debug') {
                this.winstonLogger.info(this.formatRequestLog(req));
                this.winstonLogger.info(this.formatMessage(`Headers from PAG ${JSON.stringify(req.headers)}`));
            }

            res.on('finish', () => {
                if (!process.env.TEST) {
                    // log res
                    if (res.statusCode < 400) {
                        if (this.logLevel === 'debug') {
                            this.winstonLogger.debug(this.formatResponseLog(res));
                        }
                    } else if (res.statusCode !== 404) { // Do not log 404 errors
                        this.winstonLogger.error(this.formatMessage('************* ERROR ************'));
                        this.winstonLogger.error({ ...res.params, ...res.query, ...res.body });
                        this.winstonLogger.error(this.formatResponseLog(res));
                    }
                }
            });
            next();
        };
    }

    setLogLevels() {
        this.LEVELS = {
            emerg: 0,
            alert: 1,
            crit: 2,
            error: 3,
            warning: 4,
            notice: 5,
            info: 6,
            debug: 7,
        };
    }

    getLogLevel() {
        const levelInEnv = (
            process.env.LOG_LEVEL
            && Object.keys(this.LEVELS).indexOf(process.env.LOG_LEVEL.trim().toLowerCase())
        );
        if (levelInEnv) {
            return process.env.LOG_LEVEL.trim().toLowerCase();
        }
        return process.env.STAGE === 'prod' ? 'error' : 'warning';
    }

    formatMessage(message) {
        const reqId = this.httpContext.get('request-id');
        return {
            Service: this.service,
            'Request-Id': reqId,
            Message: message,
        };
    }

    formatResponseLog(response) {
        const jsonMessage = this.formatMessage(response.statusMessage);
        const timeTaken = Date.now() - this.httpContext.get('request-start-time');
        jsonMessage.TimeTaken = timeTaken;
        jsonMessage.StatusCode = response.statusCode;
        return jsonMessage;
    }

    formatRequestLog(req) {
        const jsonMessage = this.formatMessage('');
        jsonMessage.Method = req.method;
        jsonMessage.Url = req.originalUrl || req.url;
        jsonMessage['Request-Size'] = req.headers['content-length'] ? req.headers['content-length'] : 'Not Sent By Client';
        jsonMessage['Service-Counter'] = req.headers['Service-Counter'];
        const body = { ...req.body };
        jsonMessage.Body = JSON.stringify(body);
        return jsonMessage;
    }

    error(...message) {
        const combinedMessage = message.join(' ');
        this.winstonLogger.error(this.formatMessage(combinedMessage));
    }

    warning(...message) {
        const combinedMessage = message.join(' ');
        this.winstonLogger.warning(this.formatMessage(combinedMessage));
    }

    info(...message) {
        const combinedMessage = message.join(' ');
        this.winstonLogger.info(this.formatMessage(combinedMessage));
    }

    verbose(...message) {
        const combinedMessage = message.join(' ');
        this.winstonLogger.debug(this.formatMessage(combinedMessage));
    }

    debug(...message) {
        const combinedMessage = message.join(' ');
        this.winstonLogger.debug(this.formatMessage(combinedMessage));
    }
}

module.exports = ExpressLogger;
