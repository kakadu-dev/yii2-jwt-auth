<?php
/**
 * Created by Yii2.
 * User: Yarmaliuk Mikhail
 * Date: 23.10.2018
 * Time: 13:37
 */

namespace Kakadu\Yii2JwtAuth\migrations;

use yii\db\Migration;

/**
 * Class    M181023133719Create_api_auth_tokens
 * @package Kakadu\Yii2JwtAuth\migrations
 * @author  Yarmaliuk Mikhail
 * @version 1.0
 */
class M181023133719Create_api_auth_tokens extends Migration
{
    /**
     * @var string
     */
    public $tableName = '{{%api_auth_tokens}}';

    /**
     * @inheritdoc
     */
    public function safeUp(): void
    {
        $this->createTable($this->tableName, [
            'id'              => $this->primaryKey(),
            'access_token'    => $this->string(500)->notNull(),
            'refresh_token'   => $this->string(500)->notNull(),
            'user_id'         => $this->integer(11)->notNull(),
            'access_expires'  => $this->integer(11)->defaultValue(0),
            'refresh_expires' => $this->integer(11)->defaultValue(0),
        ]);
        $this->createIndex('api_auth_tokens_user_id_index', $this->tableName, 'user_id');
    }

    /**
     * @inheritdoc
     */
    public function safeDown(): void
    {
        $this->dropTable($this->tableName);
    }
}