package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisClient interface {
	Set(key string, value interface{}, expiration int64) error
	Get(key string) (string, error)
	Del(keys ...string) error
	Exists(keys ...string) (int64, error)
	Keys(pattern string) ([]string, error)
	Pipeline(commands ...RedisCommand) ([]interface{}, error)
	Ping() error
	Close() error
	Execute(command string, args ...interface{}) (interface{}, error)
}

type redisClientImpl struct {
	client *redis.Client
}

func NewRedisClient(config *RedisConfig) RedisClient {
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", config.Host, config.Port),
		Password: config.Password,
		DB:       config.DB,
		PoolSize: config.PoolSize,
	})
	return &redisClientImpl{client: client}
}

func (c *redisClientImpl) Set(key string, value interface{}, expiration int64) error {
	if expiration > 0 {
		return c.client.Set(context.Background(), key, value, time.Duration(expiration)*time.Second).Err()
	}
	return c.client.Set(context.Background(), key, value, 0).Err()
}

func (c *redisClientImpl) Get(key string) (string, error) {
	return c.client.Get(context.Background(), key).Result()
}

func (c *redisClientImpl) Del(keys ...string) error {
	return c.client.Del(context.Background(), keys...).Err()
}

func (c *redisClientImpl) Exists(keys ...string) (int64, error) {
	return c.client.Exists(context.Background(), keys...).Result()
}

func (c *redisClientImpl) Keys(pattern string) ([]string, error) {
	return c.client.Keys(context.Background(), pattern).Result()
}

func (c *redisClientImpl) Pipeline(commands ...RedisCommand) ([]interface{}, error) {
	pipe := c.client.Pipeline()
	for _, cmd := range commands {
		pipe = pipe.Run(context.Background(), redis.Args{}.Add(cmd.Cmd).Add(cmd.Args...)...)
	}
	results, err := pipe.Results()
	if err != nil {
		return nil, err
	}
	resultsInterfaces := make([]interface{}, len(results))
	for i, r := range results {
		resultsInterfaces[i] = r
	}
	return resultsInterfaces, nil
}

func (c *redisClientImpl) Ping() error {
	return c.client.Ping(context.Background()).Err()
}

func (c *redisClientImpl) Close() error {
	return c.client.Close()
}

func (c *redisClientImpl) Execute(command string, args ...interface{}) (interface{}, error) {
	return c.client.Do(context.Background(), redis.Args{}.Add(command).Add(args...)...).Result()
}
